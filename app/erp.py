from wowipy.wowipy import WowiPy, Result
from wowipy.models import FacilityCatalogElement, ComponentCatalogElement, UnderComponent
from flask import current_app, request
import logging
from app.extensions import db
from app.models import FacilityCatalogItem, ComponentCatalogItem, UnderComponentItem, EventItem, User
from threading import Lock
from datetime import datetime
from flask_jwt_extended import get_jwt_identity

logger = logging.getLogger('root')

_wowi_client = None
_wowi_lock = Lock()


def get_wowi_client():
    global _wowi_client

    if _wowi_client is not None:
        return _wowi_client

    with _wowi_lock:
        if _wowi_client is None:
            config = current_app.config["INI_CONFIG"]
            host = config.get("OpenWowi", "host")
            user = config.get("OpenWowi", "user")
            password = config.get("OpenWowi", "pass")
            key = config.get("OpenWowi", "key")

            logger.info("Creating new WowiPy client for OpenWowi host '%s'", host)
            client = WowiPy(host, user, password, key)

            _wowi_client = client

    return _wowi_client


def with_wowi_retry(fn, *args, **kwargs):
    client = get_wowi_client()

    try:
        return fn(client, *args, **kwargs)

    except Exception as exc:
        logger.warning("WowiPy call failed, attempting retry: %s", exc)

        # Reset client
        global _wowi_client
        with _wowi_lock:
            _wowi_client = None

        client = get_wowi_client()
        return fn(client, *args, **kwargs)


def sync_facility_and_component_catalog():
    wowi = get_wowi_client()

    facility_catalog_items = wowi.get_facility_catalog()
    component_catalog_items = wowi.get_component_catalog()
    all_components = wowi.get_components(fetch_all=True)
    all_under_components = wowi.extract_under_components(all_components)

    entry: FacilityCatalogElement
    for entry in facility_catalog_items:
        find_facility = db.session.get(FacilityCatalogItem, entry.id_)
        if find_facility:
            find_facility.name = entry.name
            find_facility.status_name = entry.status_name
            find_facility.status_id = entry.status_id
            find_facility.available_building = entry.available_building
            find_facility.available_use_unit = entry.available_use_unit
            find_facility.available_economic_unit_land = entry.available_economic_unit_land
            find_facility.repair_relevance = entry.repair_relevance
        else:
            find_facility = FacilityCatalogItem(
                id=entry.id_,
                name=entry.name,
                status_name=entry.status_name,
                status_id=entry.status_id,
                available_building=entry.available_building,
                available_use_unit=entry.available_use_unit,
                available_economic_unit_land=entry.available_economic_unit_land,
                repair_relevance=entry.repair_relevance
            )
            db.session.add(find_facility)
        db.session.commit()

    entry2: ComponentCatalogElement
    for entry2 in component_catalog_items:
        find_component = db.session.get(ComponentCatalogItem, entry2.id_)
        if find_component:
            find_component.name = entry2.name
            find_component.comment = entry2.comment
            find_component.is_maintenance_relevant = entry2.is_maintenance_relevant
            find_component.is_repair_relevant = entry2.is_repair_relevant
            find_component.is_lease_relevant = entry2.is_lease_relevant
            find_component.is_warranty_relevant = entry2.is_warranty_relevant
            find_component.quantity_type_id = entry2.quantity_type_id
            find_component.quantity_type_name = entry2.quantity_type_name
            find_component.quantity_type_code = entry2.quantity_type_code
            find_component.is_metering_device = entry2.is_metering_device
            find_component.facility_catalog_item_id = entry2.facility_catalog_id
        else:
            find_component = ComponentCatalogItem(
                id=entry2.id_,
                name=entry2.name,
                comment=entry2.comment,
                is_maintenance_relevant=entry2.is_maintenance_relevant,
                is_repair_relevant=entry2.is_repair_relevant,
                is_lease_relevant=entry2.is_lease_relevant,
                is_warranty_relevant=entry2.is_warranty_relevant,
                quantity_type_id=entry2.quantity_type_id,
                quantity_type_name=entry2.quantity_type_name,
                quantity_type_code=entry2.quantity_type_code,
                is_metering_device=entry2.is_metering_device,
                facility_catalog_item_id=entry2.facility_catalog_id
            )
            db.session.add(find_component)
        db.session.commit()

    under_component: UnderComponent
    component_catalog_item: ComponentCatalogItem
    for component_catalog_id in all_under_components:
        component_catalog_item = db.session.get(ComponentCatalogItem, component_catalog_id)
        for under_component in all_under_components[component_catalog_id]:
            find_under_component = db.session.get(UnderComponentItem, under_component.id_)
            if find_under_component:
                find_under_component.name = under_component.name
            else:
                find_under_component = UnderComponentItem(
                    id=under_component.id_,
                    name=under_component.name
                )
                db.session.add(find_under_component)
            if ((not component_catalog_item.under_components) or
                    (find_under_component not in component_catalog_item.under_components)):
                component_catalog_item.under_components.append(find_under_component)
    db.session.commit()


def create_facility(wowi: WowiPy, facility_catalog_id: int, use_unit_id: int) -> int | None:
    config = current_app.config["INI_CONFIG"]
    facility_cat_item: FacilityCatalogItem
    facility_cat_item = db.session.get(FacilityCatalogItem, facility_catalog_id)
    cr_f_result: Result
    try:
        cr_f_result = wowi.create_facility(
            name=facility_cat_item.name,
            count=1,
            facility_catalog_id=facility_cat_item.id,
            facility_status_id=config.get("Handling", "component_status"),
            use_unit_id=use_unit_id
        )
        return cr_f_result.data["Id"]
    except Exception as e:
        logger.error(f"create_facility: Exception while creating facility: {str(e)}")
        return None


def create_component(wowi: WowiPy, component_catalog_id: int, facility_id: int, count: int,
                     psub_components: list[int] = None) -> int | None:
    config = current_app.config["INI_CONFIG"]
    dest_component_status = config.get("Handling", "component_status")
    bool_handling = config.get("Handling", "bool_handling")
    component_cat_item: ComponentCatalogItem
    component_cat_item = db.session.get(ComponentCatalogItem, component_catalog_id)
    if component_cat_item.is_bool:
        # Wenn der Komponententyp bool ist, sollen keine eingehenden sub_components verarbeitet werden.
        sub_components = []
    else:
        sub_components = psub_components
    if component_cat_item.is_bool and bool_handling == "sub_components":
        if count > 1:
            logger.error(f"create_component: facility_id: {facility_id} compcat {component_catalog_id} invalid count"
                         f" {count} for bool component!")
            return None
        if count == 1:
            sub_components.append(config.getint("Handling", "bool_sub_component_yes_id"))
        else:
            sub_components.append(config.getint("Handling", "bool_sub_component_no_id"))

    cr_f_result: Result
    try:
        cr_f_result = wowi.create_component(
            name=component_cat_item.name,
            count=count,
            component_catalog_id=component_cat_item.id,
            component_status_id=dest_component_status,
            facility_id=facility_id,
            under_component_ids=sub_components
        )
        return cr_f_result.data["Id"]
    except Exception as e:
        logger.error(f"create_component: Exception while creating component: {str(e)}")
        return None


def edit_component(wowi: WowiPy, component_id: int, count: int, psub_components: list[int] = None,
                   unknown: bool = False) -> int | None:
    config = current_app.config["INI_CONFIG"]
    dest_component_status = config.get("Handling", "component_status")
    bool_handling = config.get("Handling", "bool_handling")

    the_components = wowi.get_components(component_id=component_id)
    if not the_components:
        logger.error(f"app_uu_write_data: Cannot find component '{component_id}'")
        return None
    the_component = the_components[0]

    component_catalog_id = the_component.component_catalog_id
    component_cat_item: ComponentCatalogItem
    component_cat_item = db.session.get(ComponentCatalogItem, component_catalog_id)
    if component_cat_item.is_bool:
        # Wenn der Komponententyp bool ist, sollen keine eingehenden sub_components verarbeitet werden.
        sub_components = []
    else:
        sub_components = psub_components
    if component_cat_item.is_bool and bool_handling == "sub_components":
        if count > 1:
            logger.error(f"edit_component comp {component_id} compcat {component_catalog_id} invalid count"
                         f" {count} for bool component!")
            return None
        if count == 1:
            sub_components.append(config.getint("Handling", "bool_sub_component_yes_id"))
        else:
            sub_components.append(config.getint("Handling", "bool_sub_component_no_id"))

    current_user_id = int(get_jwt_identity())
    user: User
    user = User.query.get(current_user_id)
    user.last_action = datetime.now()

    if psub_components:
        psub_string = ','.join(str(e) for e in psub_components)
    else:
        psub_string = None

    new_event: EventItem
    new_event = EventItem(
        user_id=user.id,
        user_name=user.email,
        action="edit",
        ip_address=user.last_ip,
        last_lat=user.last_lat,
        last_lon=user.last_lon,
        use_unit_id=the_component.use_unit_id,
        facility_id=the_component.facility_id,
        facility_catalog_id=component_cat_item.facility_catalog_item_id,
        component_id=component_id,
        component_catalog_id=component_cat_item.id,
        sub_component_ids=psub_string
    )
    db.session.add(new_event)

    if unknown:
        # Wenn eine vorher vorhandene Komponente in der App explizit auf "Unbekannt" gesetzt wurde, muss sie entfernt
        # werden.
        new_event.action = "delete"
        wowi.delete_component(the_component.facility_id, the_component.id_)
        db.session.commit()
        return True

    cr_f_result: Result
    try:
        cr_f_result = wowi.edit_component(
            component_id=component_id,
            facility_id=the_component.facility_id,
            name=component_cat_item.name,
            count=count,
            component_catalog_id=component_cat_item.id,
            component_status_id=dest_component_status,
            under_component_ids=sub_components
        )
        db.session.commit()
        return cr_f_result.data["Id"]
    except Exception as e:
        logger.error(f"edit_component: Exception while editing component: {str(e)}")
        return None
