from .extensions import db, bcrypt
from sqlalchemy import func
from flask_login import UserMixin


component_undercomponent = db.Table(
    "component_undercomponent",
    db.Column(
        "component_id",
        db.Integer,
        db.ForeignKey("component_catalog_item.id"),
        primary_key=True,
    ),
    db.Column(
        "under_component_id",
        db.Integer,
        db.ForeignKey("under_component_item.id"),
        primary_key=True,
    ),
)


component_role = db.Table(
    "component_role",
    db.Column(
        "component_id",
        db.Integer,
        db.ForeignKey("component_catalog_item.id"),
        primary_key=True,
    ),
    db.Column(
        "role_id",
        db.Integer,
        db.ForeignKey("role.id"),
        primary_key=True,
    ),
)


class Role(db.Model):
    __tablename__ = 'role'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=True)
    components = db.relationship(
        "ComponentCatalogItem",
        secondary="component_role",
        back_populates="roles"
    )

    users = db.relationship(
        "User",
        back_populates="role"
    )


class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(128), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    last_action = db.Column(db.DateTime(timezone=True), nullable=True)
    last_lat = db.Column(db.Numeric, nullable=True)
    last_lon = db.Column(db.Numeric, nullable=True)
    last_platform = db.Column(db.String(100), nullable=True)  # ios | android
    last_version = db.Column(db.String(100), nullable=True)
    last_ip = db.Column(db.String(50), nullable=True)
    enable_score = db.Column(db.Boolean, nullable=True, default=True)
    microsoft_tid = db.Column(db.String(36), nullable=True, index=True)
    microsoft_oid = db.Column(db.String(36), nullable=True, index=True)
    role_id = db.Column(
        db.Integer,
        db.ForeignKey("role.id"),
        nullable=True
    )

    role = db.relationship(
        "Role",
        back_populates="users",
    )

    def set_password(self, password: str):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)


class TokenBlocklist(db.Model):
    __tablename__ = "token_blocklist"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())


class GeoBuilding(db.Model):
    __tablename__ = "geobuilding"

    id = db.Column(db.Integer, primary_key=True)
    erp_id = db.Column(db.Integer, nullable=False, unique=True, index=True)
    erp_idnum = db.Column(db.String(100), nullable=False)
    erp_eco_unit_id = db.Column(db.Integer, nullable=True)
    lat = db.Column(db.String(50), nullable=False)
    lon = db.Column(db.String(50), nullable=False)


class Department(db.Model):
    __tablename__ = "department"

    id = db.Column(db.Integer, primary_key=True)
    idnum = db.Column(db.String(100), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    visible = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"Department '{self.name}' ({self.id})"


class ResponsibleOfficial(db.Model):
    __tablename__ = "responsible_official"

    id = db.Column(db.Integer, primary_key=True)  # ERP-ID
    short = db.Column(db.String(50), nullable=True)
    erp_person_id = db.Column(db.Integer, nullable=False)
    erp_user_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    visible = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"ResponsibleOfficial '{self.name}' ({self.id})"


class FacilityCatalogItem(db.Model):
    __tablename__ = "facility_catalog_item"

    # ERP data
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    status_id = db.Column(db.Integer)
    status_name = db.Column(db.String(50))
    available_economic_unit_land = db.Column(db.Boolean, default=False)
    available_building = db.Column(db.Boolean, default=False)
    available_use_unit = db.Column(db.Boolean, default=False)
    repair_relevance = db.Column(db.Boolean, default=False)

    # custom data
    custom_name = db.Column(db.String(200), nullable=True)
    view_folded = db.Column(db.Boolean, default=False)

    # connections
    components = db.relationship(
        "ComponentCatalogItem",
        back_populates="facility",
        cascade="all, delete-orphan",
    )

    facilities = db.relationship(
        "FacilityItem",
        back_populates="facility_catalog_item"
    )

    @property
    def display_name(self):
        return self.custom_name or self.name


class ComponentCatalogItem(db.Model):
    __tablename__ = "component_catalog_item"

    # ERP data
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    comment = db.Column(db.Text, nullable=True)
    is_maintenance_relevant = db.Column(db.Boolean, default=False)
    is_repair_relevant = db.Column(db.Boolean, default=False)
    is_lease_relevant = db.Column(db.Boolean, default=False)
    is_warranty_relevant = db.Column(db.Boolean, default=False)
    quantity_type_id = db.Column(db.Integer, nullable=True)
    quantity_type_name = db.Column(db.String(100), nullable=True)
    quantity_type_code = db.Column(db.String(100), nullable=True)
    is_metering_device = db.Column(db.Boolean, default=False)

    # custom data
    enabled = db.Column(db.Boolean, default=False)
    custom_name = db.Column(db.String(200), nullable=True)
    is_bool = db.Column(db.Boolean, default=False)
    single_under_component = db.Column(db.Boolean, default=False)
    hide_quantity = db.Column(db.Boolean, default=False)

    # connections
    facility_catalog_item_id = db.Column(
        db.Integer,
        db.ForeignKey("facility_catalog_item.id"),
        nullable=False,
    )

    facility = db.relationship(
        "FacilityCatalogItem",
        back_populates="components",
    )

    under_components = db.relationship(
        "UnderComponentItem",
        secondary="component_undercomponent",
        back_populates="components"
    )

    roles = db.relationship(
        "Role",
        secondary="component_role",
        back_populates="components",
    )

    @property
    def display_name(self):
        return self.custom_name or self.name


class UnderComponentItem(db.Model):
    __tablename__ = "under_component_item"

    # ERP data
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))

    # custom data
    custom_name = db.Column(db.String(200), nullable=True)

    # connections
    components = db.relationship(
        "ComponentCatalogItem",
        secondary="component_undercomponent",
        back_populates="under_components",
        lazy="dynamic",
    )

    @property
    def display_name(self):
        return self.custom_name or self.name


class EventItem(db.Model):
    __tablename__ = "event_item"

    # Mögliche actions: login, logout, create, edit, delete
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    user_name = db.Column(db.String(255), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    stamp = db.Column(db.DateTime(timezone=True), server_default=func.now())
    use_unit_id = db.Column(db.Integer, nullable=True)
    use_unit_idnum = db.Column(db.String(200), nullable=True)
    last_lat = db.Column(db.Numeric, nullable=True)
    last_lon = db.Column(db.Numeric, nullable=True)
    facility_id = db.Column(db.Integer, nullable=True)
    facility_catalog_id = db.Column(db.Integer, nullable=True)
    component_id = db.Column(db.Integer, nullable=True)
    component_name = db.Column(db.String(200), nullable=True)
    component_catalog_id = db.Column(db.Integer, nullable=True)
    sub_component_ids = db.Column(db.String(255), nullable=True)
    sub_component_names = db.Column(db.String(255), nullable=True)
    scorable = db.Column(db.Boolean, default=True, nullable=True)
    ip_address = db.Column(db.String(100), nullable=True)
    quantity = db.Column(db.Integer, nullable=True)


class FacilityItem(db.Model):
    __tablename__ = "facility_item"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    facility_catalog_item_id = db.Column(
        db.Integer,
        db.ForeignKey("facility_catalog_item.id"),
        nullable=False,
    )

    facility_catalog_item = db.relationship(
        "FacilityCatalogItem",
        back_populates="facilities",
    )


class RawPayload(db.Model):
    __tablename__ = "raw_payload"

    id = db.Column(db.Integer, primary_key=True)
    stamp = db.Column(db.DateTime(timezone=True), server_default=func.now())
    payload = db.Column(db.JSON)


class EstatePictureType(db.Model):
    __tablename__ = "estate_picture_type"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(200), nullable=False)


class MediaEntity(db.Model):
    __tablename__ = "media_entity"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)


class CheckList(db.Model):
    __tablename__ = "check_list"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)

    check_list_items = db.relationship(
        "CheckListItem",
        back_populates="check_list",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="CheckListItem.position.asc(), CheckListItem.id.asc()",
    )


class CheckListItem(db.Model):
    __tablename__ = "check_list_item"

    id = db.Column(db.Integer, primary_key=True)
    position = db.Column(db.Integer, nullable=False, default=0)
    description = db.Column(db.String(255), nullable=False)
    sub_description = db.Column(db.String(255), nullable=True)
    ticket_subject = db.Column(db.String(255), nullable=True)
    ticket_content = db.Column(db.Text, nullable=True)
    dest_erp_user_id = db.Column(db.Integer, nullable=True)
    dest_erp_department_id = db.Column(db.Integer, nullable=True)

    check_list_id = db.Column(db.Integer, db.ForeignKey("check_list.id"), nullable=False)

    check_list = db.relationship(
        "CheckList",
        back_populates="check_list_items",
    )

    def __repr__(self):
        return f"CheckListItem {self.description}"
