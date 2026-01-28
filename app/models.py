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

    def set_password(self, password: str):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)


class TokenBlocklist(db.Model):
    __tablename__ = "token_blocklist"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())


class Geolocation(db.Model):
    __tablename__ = "geolocation"

    id = db.Column(db.Integer, primary_key=True)
    building_id = db.Column(db.Integer, nullable=False)
    building_idnum = db.Column(db.String(100), nullable=False)
    lat = db.Column(db.String(50), nullable=False)
    lon = db.Column(db.String(50), nullable=False)


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

    @property
    def display_name(self):
        return self.custom_name or self.name


class UnderComponentItem(db.Model):
    __tablename__ = "under_component_item"

    # ERP data
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))

    # custom data
    enabled = db.Column(db.Boolean, default=False)
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
    last_lat = db.Column(db.Numeric, nullable=True)
    last_lon = db.Column(db.Numeric, nullable=True)
    facility_id = db.Column(db.Integer, nullable=True)
    facility_catalog_id = db.Column(db.Integer, nullable=True)
    component_id = db.Column(db.Integer, nullable=True)
    component_catalog_id = db.Column(db.Integer, nullable=True)
    sub_component_ids = db.Column(db.String(255), nullable=True)
    scorable = db.Column(db.Boolean, default=True, nullable=True)
    ip_address = db.Column(db.String(100), nullable=True)


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
