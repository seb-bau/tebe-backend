import wowipy.models
from wowipy.wowipy import WowiPy, Result
from wowipy.models import (FacilityCatalogElement, ComponentCatalogElement, UnderComponentCatalogElement,
                           FacilityElement, Contractor, LicenseAgreement)
from wowipy.models import UseUnit as WowiUseUnit, BuildingLand as WowiBuildingLand
from flask import current_app
import logging
from app.extensions import db
from app.models import (FacilityCatalogItem, ComponentCatalogItem, UnderComponentItem, EventItem, User, FacilityItem,
                        EstatePictureType, MediaEntity, Department, ResponsibleOfficial, ErpUseUnit,
                        BuildingType, GeoBuilding, ContractPosition, UseUnitType)
from threading import Lock
from datetime import datetime
import re
import os
import tempfile
from typing import Optional
from decimal import Decimal

logger = logging.getLogger()


class WowiPermanentError(Exception):
    pass


class WowiTransientError(Exception):
    pass


class WowiAuthError(Exception):
    pass


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


def _extract_http_status(exc) -> int | None:
    code = getattr(exc, "status_code", None)
    if code is not None:
        try:
            # noinspection PyTypeChecker
            return int(code)
        except Exception as e:
            print(str(e))
            pass

    m = re.match(r"^\s*(\d{3})\s*:", str(exc))
    if m:
        try:
            return int(m.group(1))
        except Exception as e:
            print(str(e))
            return None
    return None


def with_wowi_retry(fn, *args, **kwargs):
    global _wowi_client

    client = get_wowi_client()

    try:
        return fn(client, *args, **kwargs)

    except WowiAuthError as exc:
        logger.info("WowiPy auth failed, resetting client: %s", exc)

        with _wowi_lock:
            _wowi_client = None

        client = get_wowi_client()
        return fn(client, *args, **kwargs)

    except Exception as exc:

        status = _extract_http_status(exc)

        # 4xx = permanent -> KEIN retry (außer evtl. auth/rate limit)

        if status is not None and 400 <= status < 500 and status not in (401, 403, 429):
            raise

        logger.info("WowiPy call failed, attempting retry: %s", exc)

        with _wowi_lock:

            _wowi_client = None

        client = get_wowi_client()

        return fn(client, *args, **kwargs)


def _raise_for_result(op_name: str, result: Result):
    status = getattr(result, "status_code", None)
    msg = getattr(result, "message", None)

    if status is None:
        raise WowiTransientError(f"{op_name}: missing status_code")

    # noinspection PyTypeChecker
    status = int(status)

    if 200 <= status < 300:
        return

    if status in (401, 403):
        raise WowiAuthError(f"{op_name}: {status} {msg}")

    if 400 <= status < 500:
        raise WowiPermanentError(f"{op_name}: {status} {msg}")

    raise WowiTransientError(f"{op_name}: {status} {msg}")


def sync_facility_catalog(wowi: WowiPy):
    facility_catalog_items = wowi.get_facility_catalog()
    fac_cat_ids = []
    entry: FacilityCatalogElement
    for entry in facility_catalog_items:
        fac_cat_ids.append(entry.id_)
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
            # noinspection PyArgumentList
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

    all_fac_cats = db.session.query(FacilityCatalogItem).all()
    for fac_cat_check in all_fac_cats:
        if fac_cat_check.id not in fac_cat_ids:
            db.session.delete(fac_cat_check)
    db.session.commit()


def sync_facility_items(wowi: WowiPy):
    all_facilities = wowi.get_facilities(fetch_all=True)
    fac_ids = []
    entry_fac: FacilityElement
    for entry_fac in all_facilities:
        fac_ids.append(entry_fac.id_)
        find_fac = db.session.get(FacilityItem, entry_fac.id_)
        if find_fac:
            find_fac.name = entry_fac.name
            find_fac.facility_catalog_item_id = entry_fac.facility_catalog_id
        else:
            # noinspection PyArgumentList
            find_fac = FacilityItem(
                id=entry_fac.id_,
                name=entry_fac.name,
                facility_catalog_item_id=entry_fac.facility_catalog_id
            )
            db.session.add(find_fac)
        db.session.commit()

    all_facs = db.session.query(FacilityItem).all()
    for fac_check in all_facs:
        if fac_check.id not in fac_ids:
            db.session.delete(fac_check)
    db.session.commit()


def sync_component_catalog(wowi: WowiPy):
    component_catalog_items = wowi.get_component_catalog()
    comp_cat_ids = []
    entry2: ComponentCatalogElement
    for entry2 in component_catalog_items:
        comp_cat_ids.append(entry2.id_)
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
            # noinspection PyArgumentList
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
        all_under_comp = []
        if entry2.allowed_under_components:
            for uc_entry in entry2.allowed_under_components:
                find_uc = db.session.get(UnderComponentItem, uc_entry.id_)
                if not find_uc:
                    logger.error(f"sync_component_catalog: Cannot find under component with id '{uc_entry.id_}' in db")
                    continue
                all_under_comp.append(find_uc)
        find_component.under_components = all_under_comp
        db.session.commit()

    all_comp_cats = db.session.query(ComponentCatalogItem).all()
    for comp_cat_check in all_comp_cats:
        if comp_cat_check.id not in comp_cat_ids:
            db.session.delete(comp_cat_check)
    db.session.commit()


def sync_under_component_catalog(wowi: WowiPy):
    under_component_catalog_items = wowi.get_under_component_catalog()
    under_comp_cat_ids = []
    entry3: UnderComponentCatalogElement
    for entry3 in under_component_catalog_items:
        under_comp_cat_ids.append(entry3.id_)
        find_under_component = db.session.get(UnderComponentItem, entry3.id_)
        if find_under_component:
            find_under_component.name = entry3.name
        else:
            # noinspection PyArgumentList
            find_under_component = UnderComponentItem(
                id=entry3.id_,
                name=entry3.name
            )
            db.session.add(find_under_component)
        db.session.commit()

    all_under = db.session.query(UnderComponentItem).all()
    for under_check in all_under:
        if under_check.id not in under_comp_cat_ids:
            db.session.delete(under_check)
    db.session.commit()


def sync_estate_picture_types(wowi: WowiPy):
    estate_picture_types = wowi.get_estate_picture_types()
    picture_type_ids = []
    for entry3 in estate_picture_types:
        picture_type_ids.append(entry3.id_)
        find_pic_type = db.session.get(EstatePictureType, entry3.id_)
        if find_pic_type:
            find_pic_type.name = entry3.name
            find_pic_type.code = entry3.code
        else:
            # noinspection PyArgumentList
            find_pic_type = EstatePictureType(
                id=entry3.id_,
                name=entry3.name,
                code=entry3.code
            )
            db.session.add(find_pic_type)
        db.session.commit()

    all_pic_types = db.session.query(EstatePictureType).all()
    for pic_check in all_pic_types:
        if pic_check.id not in picture_type_ids:
            db.session.delete(pic_check)
    db.session.commit()


def sync_media_entities(wowi: WowiPy):
    media_entities = wowi.get_media_entities()
    media_ids = []
    for entry3 in media_entities:
        media_ids.append(entry3.id_)
        find_type = db.session.get(MediaEntity, entry3.id_)
        if find_type:
            find_type.name = entry3.name
        else:
            # noinspection PyArgumentList
            find_type = MediaEntity(
                id=entry3.id_,
                name=entry3.name
            )
            db.session.add(find_type)
        db.session.commit()

    all_types = db.session.query(MediaEntity).all()
    for type_check in all_types:
        if type_check.id not in media_ids:
            db.session.delete(type_check)
    db.session.commit()


def sync_departments(wowi: WowiPy):
    def update_dep(pdep: wowipy.models.Department):
        find_dep = db.session.get(Department, pdep.id_)
        if find_dep:
            find_dep.name = pdep.name
            find_dep.idnum = pdep.id_num
        else:
            # noinspection PyArgumentList
            new_dep = Department(
                id=pdep.id_,
                idnum=pdep.id_num,
                name=pdep.name,
                visible=True
            )
            db.session.add(new_dep)
            find_dep = new_dep
        return find_dep

    def update_resp(presp: wowipy.models.ResponsibleOfficialShort):
        wowi_resp = wowi.get_responsible_officials(person_id=presp.person_id)[0]
        find_resp = db.session.get(ResponsibleOfficial, wowi_resp.id_)
        if find_resp:
            if not wowi_resp.person or not wowi_resp.person.natural_person:
                return 0
            find_resp.name = (f"{wowi_resp.person.natural_person.last_name}, "
                              f"{wowi_resp.person.natural_person.first_name}")
            find_resp.short = wowi_resp.code_short
            find_resp.erp_person_id = wowi_resp.person_id
            find_resp.erp_user_id = wowi_resp.user_id
        else:
            if not wowi_resp.person or not wowi_resp.person.natural_person:
                return 0
            # noinspection PyArgumentList
            new_resp = ResponsibleOfficial(
                id=wowi_resp.id_,
                name=(f"{wowi_resp.person.natural_person.last_name}, "
                      f"{wowi_resp.person.natural_person.first_name}"),
                short=wowi_resp.code_short,
                erp_person_id=wowi_resp.person_id,
                erp_user_id=wowi_resp.user_id,
                visible=True
            )
            db.session.add(new_resp)
            find_resp = new_resp
        return find_resp

    deps = wowi.get_departments()

    dep_ids = set()
    resp_ids_global = set()

    for tdep in deps:
        dep_ids.add(tdep.id_)
        update_dep(tdep)

        if tdep.responsible_officials is None:
            continue
        for tresp in tdep.responsible_officials:
            if tresp.id_ not in resp_ids_global:
                resp_ids_global.add(tresp.id_)
                update_resp(tresp)

    # delete officials not in ERP anymore
    for off in db.session.query(ResponsibleOfficial).all():
        if off.id not in resp_ids_global:
            db.session.delete(off)

    # delete departments not in ERP anymore
    for dep in db.session.query(Department).all():
        if dep.id not in dep_ids:
            db.session.delete(dep)

    db.session.commit()

    retmsg = f"sync_departments finished"
    print(retmsg)
    logger.info(retmsg)


def sync_erp_data():
    wowi = get_wowi_client()
    sync_use_units(wowi)
    sync_buildings(wowi)
    fix_building_types()
    sync_facility_catalog(wowi)
    sync_facility_items(wowi)
    sync_under_component_catalog(wowi)
    sync_component_catalog(wowi)
    sync_estate_picture_types(wowi)
    sync_media_entities(wowi)
    sync_departments(wowi)
    sync_contract_positions(wowi)


def sync_erp_department_data():
    wowi = get_wowi_client()
    sync_departments(wowi)


def sync_erp_use_unit_data():
    wowi = get_wowi_client()
    sync_use_units(wowi)


def sync_erp_contract_positions():
    wowi = get_wowi_client()
    sync_contract_positions(wowi)


def sync_erp_building_data():
    wowi = get_wowi_client()
    sync_buildings(wowi)


def sync_erp_component_facility_catalog():
    wowi = get_wowi_client()
    sync_facility_catalog(wowi)
    sync_under_component_catalog(wowi)
    sync_component_catalog(wowi)
    sync_facility_items(wowi)
    fix_building_types()


def create_facility(wowi: WowiPy, facility_catalog_id: int, use_unit_id: int) -> int:
    config = current_app.config["INI_CONFIG"]
    facility_cat_item: FacilityCatalogItem
    facility_cat_item = db.session.get(FacilityCatalogItem, facility_catalog_id)

    cr_f_result = wowi.create_facility(
        name=facility_cat_item.name,
        count=1,
        facility_catalog_id=facility_cat_item.id,
        facility_status_id=config.get("Handling", "component_status"),
        use_unit_id=use_unit_id
    )
    _raise_for_result("create_facility", cr_f_result)
    logger.info(f"create_facility: Use Unit '{use_unit_id}' "
                f"facility '{cr_f_result.data['Id']}' with name '{facility_cat_item.name}' created. ")

    # noinspection PyArgumentList
    new_facility_for_db = FacilityItem(
        id=cr_f_result.data["Id"],
        name=facility_cat_item.name,
        facility_catalog_item_id=facility_cat_item.id
    )
    db.session.add(new_facility_for_db)
    db.session.commit()
    return cr_f_result.data["Id"]


def create_component(
        wowi: WowiPy,
        component_catalog_id: int,
        facility_id: int,
        count: int,
        puser: Optional[User],
        puu_id: int,
        psub_components: list[int] | None = None,
        comment: str | None = None,
        ip_address: str | None = None,
        last_lat: str | None = None,
        last_lon: str | None = None,
) -> int | None:
    config = current_app.config["INI_CONFIG"]
    dest_component_status = config.get("Handling", "component_status")
    bool_handling = config.get("Handling", "bool_handling")
    component_cat_item: ComponentCatalogItem
    component_cat_item = db.session.get(ComponentCatalogItem, component_catalog_id)

    if component_cat_item.is_bool:
        sub_components = []
    else:
        sub_components = psub_components or []

    if component_cat_item.is_bool and bool_handling == "sub_components":
        if count > 1:
            logger.error(f"create_component: facility_id: {facility_id} compcat {component_catalog_id} "
                         f"invalid count {count} for bool component!")
            return None
        if count == 1:
            sub_components.append(config.getint("Handling", "bool_sub_component_yes_id"))
        else:
            sub_components.append(config.getint("Handling", "bool_sub_component_no_id"))

    comp_count = count
    if not component_cat_item.is_bool:
        for tsub in sub_components:
            sub_object = db.session.get(UnderComponentItem, tsub)
            if sub_object.name == "Nein":
                comp_count = 0
                break

    cr_f_result = wowi.create_component(
        name=component_cat_item.name,
        count=comp_count,
        component_catalog_id=component_cat_item.id,
        component_status_id=dest_component_status,
        facility_id=facility_id,
        under_component_ids=sub_components,
        comment=comment,
        repair_relevance=bool(component_cat_item.is_repair_relevant),
        lease_relevance=bool(component_cat_item.is_lease_relevant),
    )
    _raise_for_result("create_component", cr_f_result)
    logger.info(f"create_component: Use Unit '{puu_id}' "
                f"component '{cr_f_result.data['Id']}' created. Count: {count} "
                f"facility_id: {facility_id} under_component_ids: '{str(sub_components)}' "
                f"comment '{comment}'")

    sub_component_names = []
    sub_names = None
    uu_idnum = None
    try:
        if sub_components:
            for tsub in sub_components:
                tsub_obj = db.session.get(UnderComponentItem, tsub)
                sub_component_names.append(tsub_obj.name)
            sub_names = ",".join(sub_component_names)
            sub_names = sub_names[:250]
        uu = db.session.query(ErpUseUnit).filter(ErpUseUnit.erp_id == puu_id).first()
        if uu:
            uu_idnum = uu.erp_idnum

    except Exception as e:
        logger.error(f"create_component: Error while getting event info: {str(e)}")

    user_name = puser.name if puser else None
    user_id = puser.id if puser else 0

    # noinspection PyArgumentList
    new_event = EventItem(
        user_id=user_id,
        user_name=user_name,
        action="create",
        ip_address=ip_address,
        last_lat=last_lat,
        last_lon=last_lon,
        use_unit_id=puu_id,
        use_unit_idnum=uu_idnum,
        facility_id=facility_id,
        facility_catalog_id=component_cat_item.facility_catalog_item_id,
        component_id=cr_f_result.data["Id"],
        component_name=component_cat_item.name,
        component_catalog_id=component_cat_item.id,
        sub_component_ids=",".join(str(e) for e in sub_components) if sub_components else None,
        sub_component_names=sub_names,
        quantity=count
    )
    db.session.add(new_event)
    db.session.commit()
    return cr_f_result.data["Id"]


def edit_component(
        wowi: WowiPy,
        component_id: int,
        count: int,
        psub_components: list[int] | None = None,
        unknown: bool = False,
        comment: str | None = None,
        puser: User | None = None,
        ip_address: str | None = None,
        last_lat: str | None = None,
        last_lon: str | None = None,
) -> int | None:
    config = current_app.config["INI_CONFIG"]
    dest_component_status = config.get("Handling", "component_status")
    bool_handling = config.get("Handling", "bool_handling")

    the_components = wowi.get_components(component_id=component_id)
    if not the_components:
        logger.error(f"edit_component: Cannot find component '{component_id}'")
        return None
    the_component = the_components[0]

    component_catalog_id = the_component.component_catalog_id
    component_cat_item: ComponentCatalogItem
    component_cat_item = db.session.get(ComponentCatalogItem, component_catalog_id)

    if component_cat_item.is_bool:
        sub_components = []
    else:
        sub_components = psub_components or []

    if component_cat_item.is_bool and bool_handling == "sub_components":
        if count > 1:
            logger.error(f"edit_component comp {component_id} compcat {component_catalog_id} "
                         f"invalid count {count} for bool component!")
            return None
        if count == 1:
            sub_components.append(config.getint("Handling", "bool_sub_component_yes_id"))
        else:
            sub_components.append(config.getint("Handling", "bool_sub_component_no_id"))

    comp_count = count
    if not component_cat_item.is_bool:
        for tsub in sub_components:
            sub_object = db.session.get(UnderComponentItem, tsub)
            if sub_object.name == "Nein":
                comp_count = 0
                break

    if puser is not None:
        puser.last_action = datetime.now()

    sub_component_names = []
    sub_names = None
    uu_idnum = None
    try:
        if sub_components:
            for tsub in sub_components:
                tsub_obj = db.session.get(UnderComponentItem, tsub)
                sub_component_names.append(tsub_obj.name)
            sub_names = ",".join(sub_component_names)
            sub_names = sub_names[:250]
        uu = db.session.query(ErpUseUnit).filter(ErpUseUnit.erp_id == the_component.use_unit_id).first()
        if uu:
            uu_idnum = uu.erp_idnum

    except Exception as e:
        logger.error(f"edit_component: Error while collecting event info: {str(e)}")

    psub_string = ",".join(str(e) for e in sub_components) if sub_components else None

    component_subs = []
    if the_component.under_components:
        for csub in the_component.under_components:
            component_subs.append(csub.id_)

    component_subs.sort()
    sub_components.sort()

    local_comment = the_component.comment
    if isinstance(local_comment, str):
        local_comment = local_comment.strip()
    if not local_comment:
        local_comment = None

    local_count = int(the_component.count)

    if component_subs == sub_components and local_comment == comment and local_count == comp_count:
        # No change detected
        if puser is not None:
            db.session.commit()
        return True

    # # Is there a difference to the erp stored component?
    # is_different = False
    # if count != the_component.count:
    #     is_different = True
    # if not is_different:
    #     return True
    #
    # print(the_component.under_components)
    # print(psub_components)

    if the_component.facility_id is None:
        logger.error(f"edit_component: Component {the_component.id_} has no facility id")
        return True

    cr_f_result = wowi.edit_component(
        component_id=component_id,
        facility_id=the_component.facility_id,
        name=component_cat_item.name,
        count=comp_count,
        component_catalog_id=component_cat_item.id,
        component_status_id=dest_component_status,
        under_component_ids=sub_components,
        comment=comment,
        repair_relevance=the_component.repair_relevance,
        lease_relevance=the_component.lease_relevance,
        acquisition_date=the_component.acquisition_date,
    )
    _raise_for_result("edit_component", cr_f_result)
    logger.info(f"edit_component: Use Unit '{the_component.use_unit_id}' "
                f"component '{component_id}' edited. Count: {comp_count} "
                f"facility_id: {the_component.facility_id} under_component_ids: '{str(sub_components)}' "
                f"comment '{comment}'")

    new_event = None
    if puser is not None:
        # noinspection PyArgumentList
        new_event = EventItem(
            user_id=puser.id,
            user_name=puser.name,
            action="edit",
            ip_address=ip_address,
            last_lat=last_lat,
            last_lon=last_lon,
            use_unit_id=the_component.use_unit_id,
            use_unit_idnum=uu_idnum,
            facility_id=the_component.facility_id,
            facility_catalog_id=component_cat_item.facility_catalog_item_id,
            component_id=component_id,
            component_name=the_component.name,
            component_catalog_id=component_cat_item.id,
            sub_component_ids=psub_string,
            sub_component_names=sub_names,
            quantity=comp_count
        )

    if unknown:
        if new_event is not None:
            new_event.action = "delete"
        wowi.delete_component(the_component.facility_id, the_component.id_)
        if new_event is not None:
            db.session.add(new_event)
        db.session.commit()
        return True

    if new_event is not None:
        db.session.add(new_event)
    db.session.commit()
    return cr_f_result.data["Id"]


def get_responsible_official(wowi: WowiPy, use_unit_id: int, department_id: int) -> ResponsibleOfficial | None:
    uu = db.session.query(ErpUseUnit).filter(ErpUseUnit.erp_id == use_unit_id).first()
    if not uu:
        logger.error(f"get_responsible_official: UseUnit '{use_unit_id}' not found in db")
        return None
    eco_unit_id = uu.erp_eco_unit_id
    eco_unit_jur = wowi.get_economic_unit_jurisdictions(economic_unit_id=eco_unit_id)
    if not eco_unit_jur:
        logger.error(f"get_responsible_official: No jurisdiction entry for eco unit '{eco_unit_id}'")
        return None
    for entry in eco_unit_jur[0].economic_unit_jurisdiction_list:
        if entry.department_id == department_id:
            resp_id = entry.responsible_official.id_
            tresp = db.session.get(ResponsibleOfficial, resp_id)
            if not tresp:
                logger.error(f"get_responsible_official: Cannot find official '{resp_id}' in local db")
                return None
            return tresp
    logger.error(f"get_responsible_official: No entry for eco-unit '{eco_unit_id}' department '{department_id}'")
    return None


def download_floor_plan(wowi: WowiPy, uu_id: int):
    uumedia = wowi.get_media(entity_name="UseUnit", entity_id=uu_id)
    # Es kann mehrere Grundrisse geben. Wir möchten den neusten ausgeben
    dest_media_entry = None
    for entry in uumedia:
        if (entry.picture_type_name == "Grundriss"
                or entry.remark == "Grundriss"
                or (entry.remark and "Grundriss" in entry.remark)):
            if not dest_media_entry:
                dest_media_entry = entry
            else:
                # Wenn dieser Eintrag neuer ist - überschreiben
                if (datetime.strptime(entry.creation_date, "%Y-%m-%d") >
                        datetime.strptime(dest_media_entry.creation_date, "%Y-%m-%d")):
                    dest_media_entry = entry
    if dest_media_entry:
        print(f"MEDIA ID {dest_media_entry.file_guid}")
        tmpdir = os.path.join(tempfile.gettempdir(), "tebe_use_unit_floor_plans")
        os.makedirs(tmpdir, exist_ok=True)
        file_path = os.path.join(tmpdir, dest_media_entry.file_name)
        wowi.download_media("UseUnit", dest_media_entry.file_guid, tmpdir, dest_media_entry.file_name)
        return {
            "file_path": file_path,
            "file_name": dest_media_entry.file_name
        }
    return None


def download_photo(wowi: WowiPy, entity_name: str, media_id: int):
    uumedia = wowi.get_media(entity_name=entity_name, media_id=media_id)
    if not uumedia:
        return None
    dest_media_entry = uumedia[0]
    tmpdir = os.path.join(tempfile.gettempdir(), "tebe_photos")
    os.makedirs(tmpdir, exist_ok=True)
    file_path = os.path.join(tmpdir, dest_media_entry.file_name)
    wowi.download_media(entity_name, dest_media_entry.file_guid, tmpdir, dest_media_entry.file_name)
    return {
        "file_path": file_path,
        "file_name": dest_media_entry.file_name
    }


def get_contracts_for_use_unit(use_unit_id: int, include_vacancy: bool = False) -> list | None:
    retval = []
    wowi = get_wowi_client()
    targs = {"useUnitId": use_unit_id}
    contracts = wowi.get_license_agreements(add_args=targs, add_contractors=True)
    for contract in contracts:
        if contract.restriction_of_use.is_vacancy and not include_vacancy:
            continue
        if contract.end_of_contract:
            dt_end = None
            if isinstance(contract.end_of_contract, datetime):
                dt_end = contract.end_of_contract
            elif isinstance(contract.end_of_contract, str):
                try:
                    dt_end = datetime.strptime(contract.end_of_contract, "%Y-%m-%d")
                except ValueError:
                    logger.error(f"get_contracts_for_use_unit: end date of contract {contract.id_} is invalid: "
                                 f"{contract.end_of_contract}")
                    continue
            if not dt_end:
                logger.error(f"get_contracts_for_use_unit: end date of contract {contract.id_} has invalid type: "
                             f"{type(contract.end_of_contract)}")
                continue

            if datetime.now() > dt_end:
                continue

        retval.append(contract)
    return retval


def get_contractors_for_use_unit(wowi: WowiPy, use_unit_id_num: str) \
        -> tuple[None, None] | tuple[list[Contractor] | None, LicenseAgreement]:
    contract = wowi.get_license_agreements(use_unit_idnum=use_unit_id_num,
                                           license_agreement_active_on=datetime.now())
    if not contract:
        msg = f"get_contractors_for_use_unit: Cannot find contract for use unit '{use_unit_id_num}'"
        logger.warning(msg)
        print(msg)
        return None, None

    if len(contract) > 1:
        msg = f"get_contractors_for_use_unit: More than one contract for use unit '{use_unit_id_num}'"
        logger.warning(msg)
        print(msg)

    the_contract = contract[0]
    contractors = None
    if not the_contract.restriction_of_use.is_vacancy:
        contractors = wowi.get_contractors(license_agreement_id=the_contract.id_,
                                           contractual_use_active_on=datetime.now())

    return contractors, the_contract


def filter_contractors(contractor_list) -> dict:
    ret_dict = {
        "last1": None,
        "last2": None,
        "first1": None,
        "first2": None
    }
    if not contractor_list:
        return ret_dict

    for contractor in contractor_list:
        if contractor.contractor_type.name == "1. Vertragsnehmer":
            if contractor.person.is_natural_person:
                ret_dict["first1"] = contractor.person.natural_person.first_name
                ret_dict["last1"] = contractor.person.natural_person.last_name
            else:
                ret_dict["last1"] = contractor.person.legal_person.long_name1
        elif contractor.contractor_type.name == "2. Vertragsnehmer":
            if contractor.person.is_natural_person:
                ret_dict["first2"] = contractor.person.natural_person.first_name
                ret_dict["last2"] = contractor.person.natural_person.last_name
            else:
                ret_dict["last2"] = contractor.person.legal_person.long_name1

    return ret_dict


def sync_use_units(wowi: WowiPy):
    use_units = wowi.get_use_units(fetch_all=True)
    uu_ids = []
    entry: WowiUseUnit
    counter = 0
    total = len(use_units)
    non_existing_uus = 0
    non_existing_building = 0
    for entry in use_units:
        counter += 1
        print(f"UseUnit {counter} of {total}")
        # Check if Use unit or building was torn down
        building = db.session.query(GeoBuilding).filter(GeoBuilding.erp_id == entry.building_land.id_).first()
        if not building:
            non_existing_building += 1
            continue
        if entry.exit_date:
            try:
                exit_date = datetime.strptime(str(entry.exit_date), "%Y-%m-%d")
                if exit_date < datetime.now():
                    non_existing_uus += 1
                    continue
            except ValueError:
                logger.error(f"sync_use_unit: Wrong date format: '{entry.exit_date}'")
        contract: LicenseAgreement
        contractors, contract = get_contractors_for_use_unit(wowi, use_unit_id_num=entry.id_num)
        contr_list = filter_contractors(contractors)

        type_name = entry.current_use_unit_type.use_unit_usage_type.name
        if type_name == "Wohnung":
            uu_type = UseUnitType.APARTMENT
        elif type_name == "Gewerbe":
            uu_type = UseUnitType.COMMERCIAL
        elif type_name == "Garage":
            uu_type = UseUnitType.GARAGE
        elif type_name == "Stellplatz":
            uu_type = UseUnitType.PARKING
        else:
            uu_type = UseUnitType.OTHER

        contract_idnum = None
        contract_id = None
        contract_start = None
        contract_end = None
        contract_is_vacancy = False
        contract_is_cancelled = False
        if contract:
            contract_idnum = contract.id_num
            contract_id = contract.id_
            contract_end = contract.end_of_contract
            contract_start = contract.start_contract
            if contract.status_contract.name == "gekündigt":
                contract_is_cancelled = True
            if contract.restriction_of_use.is_vacancy:
                contract_is_vacancy = True

        uu_ids.append(entry.id_)
        find_use_unit = db.session.query(ErpUseUnit).filter(ErpUseUnit.erp_id == entry.id_).first()
        if find_use_unit:
            find_use_unit.use_unit_type = uu_type
            find_use_unit.erp_id = entry.id_
            find_use_unit.erp_eco_unit_id = entry.economic_unit.id_
            find_use_unit.erp_building_id = entry.building_land.id_
            find_use_unit.erp_idnum = entry.id_num
            find_use_unit.contractor_first_name_1 = contr_list.get("first1")
            find_use_unit.contractor_first_name_2 = contr_list.get("first2")
            find_use_unit.contractor_last_name_1 = contr_list.get("last1")
            find_use_unit.contractor_last_name_2 = contr_list.get("last2")
            find_use_unit.erp_contract_id = contract_id
            find_use_unit.erp_contract_idnum = contract_idnum
            find_use_unit.contract_start = contract_start
            find_use_unit.contract_end = contract_end
            find_use_unit.is_vacancy = contract_is_vacancy
            find_use_unit.is_cancelled = contract_is_cancelled
            find_use_unit.description_of_position = entry.description_of_position
        else:
            # noinspection PyArgumentList
            find_use_unit = ErpUseUnit(
                use_unit_type=uu_type,
                erp_id=entry.id_,
                erp_idnum=entry.id_num,
                erp_building_id=entry.building_land.id_,
                erp_eco_unit_id=entry.economic_unit.id_,
                contractor_last_name_1=contr_list.get("last1"),
                contractor_first_name_1=contr_list.get("first1"),
                contractor_last_name_2=contr_list.get("last2"),
                contractor_first_name_2=contr_list.get("first2"),
                erp_contract_id=contract_id,
                erp_contract_idnum=contract_idnum,
                contract_start=contract_start,
                contract_end=contract_end,
                is_vacancy=contract_is_vacancy,
                is_cancelled=contract_is_cancelled,
                description_of_position=entry.description_of_position
            )
            db.session.add(find_use_unit)
        db.session.commit()

    print(f"non existing uus: {non_existing_uus}")
    print(f"non existing buildings: {non_existing_building}")
    all_uus = db.session.query(ErpUseUnit).all()
    for all_uu_check in all_uus:
        if all_uu_check.erp_id not in uu_ids:
            db.session.delete(all_uu_check)
    db.session.commit()


def sync_contract_positions(wowi: WowiPy):
    cpos_complete = wowi.get_all_contract_positions(contract_positions_active_on=datetime.now(),
                                                    license_agreement_active_on=datetime.now())
    rent_accounts_complete = wowi.get_rent_accounts(license_agreement_active_on=datetime.now(), fetch_all=True)
    contracts_complete = wowi.get_license_agreements(license_agreement_active_on=datetime.now(), fetch_all=True)
    opn_pos_complete = []
    tall_uu = db.session.query(ErpUseUnit).all()
    total = len(tall_uu)
    tcounter = 0
    for tx in tall_uu:
        tcounter += 1
        print(f"{tcounter} / {total}")
        tpos = wowi.get_open_rent_account_positions(use_unit_id=tx.erp_id,
                                                    license_agreement_active_on=datetime.now(),
                                                    fetch_all=True)
        opn_pos_complete.extend(tpos)

    CENT = Decimal("0.01")

    def money(value) -> Decimal:
        if value is None:
            return Decimal("0.00")
        return Decimal(str(value)).quantize(CENT)

    def get_contract(erp_contract_id: int) -> LicenseAgreement | None:
        for tentry in contracts_complete:
            if tentry.id_ == erp_contract_id:
                return tentry
        return None

    def get_cpos(use_unit_id: int) -> list:
        retval = []
        for tentry in cpos_complete:
            if tentry.valid_contract_position.name == "ungültig":
                continue
            if tentry.license_agreement.use_unit.id_ == use_unit_id:
                retval.append(tentry)
        return retval

    def get_account_bal(erp_contract_id: int) -> Decimal:
        for tentry in rent_accounts_complete:
            if tentry.license_agreement.get("id") == erp_contract_id:
                return money(tentry.total_balance_by_open_items)
        return Decimal("0.00")

    def get_dunning_data(erp_contract: LicenseAgreement) -> dict:
        fallback = {}
        if erp_contract.dunning_data and erp_contract.dunning_data.dunning_level:
            return {
                "dunning_id": erp_contract.dunning_data.dunning_level.id_,
                "dunning_code": erp_contract.dunning_data.dunning_level.code
            }
        return fallback

    def get_bal(erp_contract_id: int, booking_text_whitelist: list) -> Decimal:
        tsum = Decimal("0.00")
        for tentry in opn_pos_complete:
            if tentry.license_agreement.get("id") == erp_contract_id and tentry.booking_text_open_items:
                if (any(term.lower() in tentry.booking_text_open_items.lower() for term in booking_text_whitelist)
                        or tentry.debit_credit == "C"):
                    amount = money(tentry.amount)
                    if tentry.debit_credit == "D":
                        # SOLL
                        tsum = tsum - amount
                    else:
                        # HABEN
                        tsum = tsum + amount
        if tsum > 0:
            tsum = Decimal("0.00")
        return tsum.quantize(CENT)

    def calc_arrears(tentry: ErpUseUnit, ttotal_rent: dict, booking_text_whitelist: list) -> dict:
        fallback = {
            "month_arrears": Decimal("0"),
            "balance_account": Decimal("0"),
            "balance_positions": Decimal("0"),
            "total_rent": Decimal("0")
        }
        current_uu_rent = ttotal_rent.get(tentry.erp_contract_id)
        if not current_uu_rent:
            terrmsg = (f"sync_contract_positions: Cannot calculate rent for uu {tentry.erp_idnum} contract "
                       f"{tentry.erp_contract_idnum}")
            print(terrmsg)
            logger.warning(terrmsg)
            return fallback
        # noinspection PyTypeChecker
        current_uu_rent = money(current_uu_rent)

        current_uu_balance = get_bal(tentry.erp_contract_id, booking_text_whitelist)
        if not current_uu_balance:
            return fallback

        if current_uu_balance >= 0:
            return fallback

        tretval = {
            "month_arrears": abs((current_uu_balance / current_uu_rent).quantize(CENT)),
            "balance_account": get_account_bal(tentry.erp_contract_id),
            "balance_positions": current_uu_balance.quantize(CENT),
            "total_rent": current_uu_rent.quantize(CENT)
        }
        return tretval

    erp_use_units = db.session.query(ErpUseUnit).all()
    pos_ids = []
    total_rent = {}
    counter = 0
    total = len(erp_use_units)
    config = current_app.config["INI_CONFIG"]
    btext_whitelist_raw = config.get("Handling", "whitelist_rent_booking_text", fallback=None)
    btext_whitelist = btext_whitelist_raw.split("|") or []

    for entry in erp_use_units:
        print(f"{counter} / {total}")
        counter += 1
        if entry.contractor_last_name_1 is None:
            entry.month_in_arrears = Decimal("0")
            continue
        cpositions = get_cpos(entry.erp_id)
        if not cpositions:
            entry.month_in_arrears = Decimal("0")
            errmsg = f"No contract positions for erp_use_unit {entry.erp_id}"
            logger.warning(errmsg)
            continue

        for cpos in cpositions:
            if cpos.valid_contract_position.name == "ungültig":
                continue
            pos_ids.append(cpos.id_)
            local_cposition = (db.session.query(ContractPosition)
                               .filter(ContractPosition.erp_id == cpos.id_)
                               .first())
            if local_cposition:
                local_cposition.net_amount = cpos.net_amount
                local_cposition.amount = cpos.amount
                local_cposition.vat_rate_id = cpos.vat_rate.id_
                local_cposition.vat_rate_code = cpos.vat_rate.code
                local_cposition.position_type_id = cpos.contract_position_type.id_
                local_cposition.position_type_name = cpos.contract_position_type.name
            else:
                # noinspection PyArgumentList
                local_cposition = ContractPosition(
                    erp_id=cpos.id_,
                    net_amount=cpos.net_amount,
                    amount=cpos.amount,
                    erp_contract_id=cpos.license_agreement.id_,
                    vat_rate_id=cpos.vat_rate.id_,
                    vat_rate_code=cpos.vat_rate.code,
                    position_type_id=cpos.contract_position_type.id_,
                    position_type_name=cpos.contract_position_type.name,
                    erp_use_unit_id=entry.erp_id
                )
                db.session.add(local_cposition)
            contract_rent = total_rent.get(local_cposition.erp_contract_id) or Decimal("0.00")
            contract_rent += money(local_cposition.amount)
            total_rent[local_cposition.erp_contract_id] = contract_rent.quantize(CENT)
        # Mietrückstand berechnen
        calc_arrears_for = [UseUnitType.APARTMENT, UseUnitType.COMMERCIAL]
        if entry.use_unit_type in calc_arrears_for:
            arrear_result = calc_arrears(entry, total_rent, btext_whitelist)
            entry.month_in_arrears = arrear_result.get("month_arrears")
            entry.rent_total = arrear_result.get("total_rent")
            entry.balance_positions = arrear_result.get("balance_positions")
            entry.balance_account = arrear_result.get("balance_account")
        else:
            entry.month_in_arrears = Decimal("0")
            entry.rent_total = Decimal("0")
            entry.balance_positions = Decimal("0")
            entry.balance_account = Decimal("0")

        # Mahndaten auslesen
        the_erp_contract = get_contract(entry.erp_contract_id)
        if not the_erp_contract:
            entry.dunning_id = None
            entry.dunning_code = None
        else:
            tdunning_data = get_dunning_data(the_erp_contract)
            if not tdunning_data:
                entry.dunning_id = None
                entry.dunning_code = None
            else:
                entry.dunning_id = tdunning_data["dunning_id"]
                entry.dunning_code = tdunning_data["dunning_code"]

    db.session.commit()
    all_pos = db.session.query(ContractPosition).all()
    for all_uu_check in all_pos:
        if all_uu_check.erp_id not in pos_ids:
            db.session.delete(all_uu_check)
    db.session.commit()


def sync_buildings(wowi: WowiPy):
    buildings = wowi.get_building_lands(fetch_all=True)
    b_ids = []
    entry: WowiBuildingLand
    counter = 0
    total = len(buildings)
    for entry in buildings:
        counter += 1
        print(f"Building {counter} of {total}")
        if entry.exit_date:
            try:
                exit_date = datetime.strptime(str(entry.exit_date), "%Y-%m-%d")
                if exit_date < datetime.now():
                    continue
            except ValueError:
                logger.error(f"sync_use_unit: Wrong date format: '{entry.exit_date}'")
        # HARDCODED TENANT SPECIFIC VALUES - NEED TO FIX THIS
        if entry.id_num.startswith("11") or entry.id_num.startswith("13"):
            continue
        # HARDCODED END
        type_name = entry.building.building_type.name

        members_living = ["Einfamilienhaus", "Mehrfamilienhaus", "Zweifamilienhaus", "Wohn- und Geschäftshaus",
                          "Doppelhaushälfte"]
        members_parking = ["Carport", "Garage", "Hochgarage", "Parkhaus", "Stellplatz", "Tiefgarage"]
        members_office = ["Einkaufszentrum", "Bürogebäude", "Fabrikgebäude", "Supermarkt"]

        if type_name in members_living:
            b_type = BuildingType.LIVING
        elif type_name in members_parking:
            b_type = BuildingType.PARKING
        elif type_name in members_office:
            b_type = BuildingType.OFFICE
        else:
            b_type = BuildingType.OTHER

        b_ids.append(entry.id_)
        find_building = db.session.query(GeoBuilding).filter(GeoBuilding.erp_id == entry.id_).first()
        if find_building:
            find_building.building_type = b_type
            find_building.erp_eco_unit_id = entry.economic_unit.id_
            find_building.erp_idnum = entry.id_num
            find_building.street = entry.estate_address.street
            find_building.postcode = entry.estate_address.zip_
            find_building.town = entry.estate_address.town
            find_building.street_complete = entry.estate_address.street_complete
        else:
            # noinspection PyArgumentList
            find_use_unit = GeoBuilding(
                building_type=b_type,
                erp_id=entry.id_,
                erp_idnum=entry.id_num,
                erp_eco_unit_id=entry.economic_unit.id_,
                street=entry.estate_address.street,
                street_complete=entry.estate_address.street_complete,
                postcode=entry.estate_address.zip_,
                town=entry.estate_address.town,
            )
            db.session.add(find_use_unit)
        db.session.commit()

    all_bs = db.session.query(GeoBuilding).all()
    for all_b_check in all_bs:
        if all_b_check.erp_id not in b_ids:
            db.session.delete(all_b_check)
    db.session.commit()


def fix_building_types():
    buildings = db.session.query(GeoBuilding).all()
    for building in buildings:
        all_use_units_same_type = True
        all_use_units_type = None
        use_units = db.session.query(ErpUseUnit).filter(ErpUseUnit.erp_building_id == building.erp_id)
        for uu in use_units:
            if not all_use_units_type:
                all_use_units_type = uu.use_unit_type
            else:
                if all_use_units_type != uu.use_unit_type:
                    all_use_units_same_type = False
                    break

        ret_bb_type: BuildingType
        if all_use_units_same_type:
            if all_use_units_type == UseUnitType.GARAGE or all_use_units_type == UseUnitType.PARKING:
                building.building_type = BuildingType.PARKING
            elif all_use_units_type == UseUnitType.COMMERCIAL:
                building.building_type = BuildingType.OFFICE

        db.session.commit()
