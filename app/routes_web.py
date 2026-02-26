from flask import render_template, request, flash, abort, redirect, url_for
from app.models import User, Role, FacilityCatalogItem, ComponentCatalogItem, UnderComponentItem
from app.models import EventItem, Department, ResponsibleOfficial, CheckList, CheckListItem
from app.extensions import db
from flask import current_app
from flask_login import login_required, current_user
from functools import wraps
from sqlalchemy import or_
from wowicache.models import WowiCache, UseUnit
from datetime import datetime, timedelta, time, timezone
import logging
from sqlalchemy import func
from app.entra_sync import sync_entra_users

logger = logging.getLogger()


def register_routes_web(app):
    def admin_required(view_func):
        @wraps(view_func)
        @login_required
        def wrapped_view(*args, **kwargs):
            if not getattr(current_user, "is_admin", False):
                abort(403)
            return view_func(*args, **kwargs)

        return wrapped_view

    @app.route("/")
    @admin_required
    def index():
        now = datetime.now(timezone.utc)
        year_start = now - timedelta(days=364)
        last_7 = now - timedelta(days=7)
        last_30 = now - timedelta(days=30)

        total_users = db.session.query(func.count(User.id)).scalar() or 0
        active_users = db.session.query(func.count(User.id)).filter(User.is_active.is_(True)).scalar() or 0

        total_events = db.session.query(func.count(EventItem.id)).scalar() or 0
        total_changes = (
            db.session.query(func.count(EventItem.id))
            .filter(EventItem.action.in_(["create", "edit", "upl_photo"]))
            .scalar()
            or 0
        )

        active_users_7d = (
            db.session.query(func.count(func.distinct(EventItem.user_id)))
            .filter(EventItem.stamp >= last_7)
            .scalar()
            or 0
        )
        active_users_30d = (
            db.session.query(func.count(func.distinct(EventItem.user_id)))
            .filter(EventItem.stamp >= last_30)
            .scalar()
            or 0
        )

        changes_7d = (
            db.session.query(func.count(EventItem.id))
            .filter(EventItem.action.in_(["create", "edit", "upl_photo"]))
            .filter(EventItem.stamp >= last_7)
            .scalar()
            or 0
        )
        changes_30d = (
            db.session.query(func.count(EventItem.id))
            .filter(EventItem.action.in_(["create", "edit", "upl_photo"]))
            .filter(EventItem.stamp >= last_30)
            .scalar()
            or 0
        )

        daily_rows = (
            db.session.query(func.date(EventItem.stamp).label("d"), func.count(EventItem.id).label("c"))
            .filter(EventItem.action.in_(["create", "edit", "upl_photo"]))
            .filter(EventItem.stamp >= year_start)
            .group_by("d")
            .order_by("d")
            .all()
        )

        daily_map = {str(d): int(c) for (d, c) in daily_rows if d is not None}

        labels = []
        values = []
        for i in range(365):
            day = (year_start.date() + timedelta(days=i)).isoformat()
            labels.append(day)
            values.append(daily_map.get(day, 0))

        action_rows_30d = (
            db.session.query(EventItem.action, func.count(EventItem.id))
            .filter(EventItem.stamp >= last_30)
            .group_by(EventItem.action)
            .order_by(func.count(EventItem.id).desc())
            .all()
        )
        action_labels = [a or "unknown" for (a, _) in action_rows_30d]
        action_values = [int(c) for (_, c) in action_rows_30d]

        top_users_30d = (
            db.session.query(EventItem.user_name, func.count(EventItem.id).label("c"))
            .filter(EventItem.action.in_(["create", "edit", "upl_photo"]))
            .filter(EventItem.stamp >= last_30)
            .group_by(EventItem.user_name)
            .order_by(func.count(EventItem.id).desc(), EventItem.user_name.asc())
            .limit(10)
            .all()
        )
        top_users_rows = [{"user_name": u, "changes": int(c)} for (u, c) in top_users_30d]

        recent_changes = (
            db.session.query(EventItem)
            .filter(EventItem.action.in_(["create", "edit", "upl_photo"]))
            .order_by(EventItem.stamp.desc(), EventItem.id.desc())
            .limit(20)
            .all()
        )

        return render_template(
            "index.html",
            stats={
                "total_users": total_users,
                "active_users": active_users,
                "total_events": total_events,
                "total_changes": total_changes,
                "active_users_7d": active_users_7d,
                "active_users_30d": active_users_30d,
                "changes_7d": changes_7d,
                "changes_30d": changes_30d,
            },
            chart_year={"labels": labels, "values": values},
            chart_actions_30d={"labels": action_labels, "values": action_values},
            top_users_rows=top_users_rows,
            recent_changes=recent_changes,
        )

    # ---------------------------------------------------------
    # Departments (Abteilungen) – nur visibility änderbar
    # ---------------------------------------------------------
    @app.route("/admin/departments")
    @admin_required
    def admin_departments_list():
        departments = Department.query.order_by(Department.name.asc(), Department.id.asc()).all()
        return render_template("admin/departments_list.html", departments=departments)

    @app.route("/admin/departments/<int:department_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_departments_edit(department_id):
        department = Department.query.get_or_404(department_id)

        if request.method == "POST":
            # Nur visible darf geändert werden
            department.visible = bool(request.form.get("visible"))
            db.session.commit()
            flash("Abteilung wurde aktualisiert.", "success")
            return redirect(url_for("admin_departments_list"))

        return render_template("admin/department_form.html", department=department)

    # ---------------------------------------------------------
    # ResponsibleOfficial (Ansprechpartner) – nur visibility änderbar
    # ---------------------------------------------------------
    @app.route("/admin/officials")
    @admin_required
    def admin_officials_list():
        officials = ResponsibleOfficial.query.order_by(ResponsibleOfficial.name.asc(),
                                                       ResponsibleOfficial.id.asc()).all()
        return render_template("admin/officials_list.html", officials=officials)

    @app.route("/admin/officials/<int:official_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_officials_edit(official_id):
        official = ResponsibleOfficial.query.get_or_404(official_id)

        if request.method == "POST":
            # Nur visible darf geändert werden
            official.visible = bool(request.form.get("visible"))
            db.session.commit()
            flash("Ansprechpartner wurde aktualisiert.", "success")
            return redirect(url_for("admin_officials_list"))

        return render_template("admin/official_form.html", official=official)

    # ---------------------------------------------------------
    # Checklisten
    # ---------------------------------------------------------
    @app.route("/admin/checklists")
    @admin_required
    def admin_checklists_list():
        checklists = CheckList.query.order_by(CheckList.name.asc(), CheckList.id.asc()).all()
        return render_template("admin/checklists_list.html", checklists=checklists)

    @app.route("/admin/checklists/create", methods=["GET", "POST"])
    @admin_required
    def admin_checklists_create():
        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            if not name:
                flash("Name ist ein Pflichtfeld.", "danger")
                return redirect(url_for("admin_checklists_create"))

            cl = CheckList(name=name)
            db.session.add(cl)
            db.session.commit()
            flash("Checkliste wurde erstellt.", "success")
            return redirect(url_for("admin_checklists_edit", checklist_id=cl.id))

        return render_template("admin/checklist_form.html", checklist=None)

    @app.route("/admin/checklists/<int:checklist_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_checklists_edit(checklist_id):
        checklist = CheckList.query.get_or_404(checklist_id)

        # Checklisten-Name speichern (oben im gleichen Screen)
        if request.method == "POST" and request.form.get("_form") == "checklist":
            name = (request.form.get("name") or "").strip()
            if not name:
                flash("Name ist ein Pflichtfeld.", "danger")
                return redirect(url_for("admin_checklists_edit", checklist_id=checklist.id))

            checklist.name = name
            db.session.commit()
            flash("Checkliste wurde aktualisiert.", "success")
            return redirect(url_for("admin_checklists_edit", checklist_id=checklist.id))

        departments = Department.query.filter_by(visible=True).order_by(Department.name.asc()).all()
        officials = ResponsibleOfficial.query.filter_by(visible=True).order_by(ResponsibleOfficial.name.asc()).all()
        return render_template(
            "admin/checklist_form.html",
            checklist=checklist,
            departments=departments,
            officials=officials,
        )

    @app.route("/admin/checklists/<int:checklist_id>/delete", methods=["POST"])
    @admin_required
    def admin_checklists_delete(checklist_id):
        checklist = CheckList.query.get_or_404(checklist_id)
        db.session.delete(checklist)
        db.session.commit()
        flash("Checkliste wurde gelöscht.", "info")
        return redirect(url_for("admin_checklists_list"))

    # -------------------------
    # CheckListItems (nur innerhalb der Checklisten-Edit-Ansicht)
    # -------------------------
    @app.route("/admin/checklists/<int:checklist_id>/items/create", methods=["POST"])
    @admin_required
    def admin_checklist_items_create(checklist_id):
        checklist = CheckList.query.get_or_404(checklist_id)

        description = (request.form.get("description") or "").strip()
        sub_description = (request.form.get("sub_description") or "").strip() or None
        ticket_subject = (request.form.get("ticket_subject") or "").strip() or None
        ticket_content = (request.form.get("ticket_content") or "").strip() or None
        dest_erp_user_id = request.form.get("dest_erp_user_id", type=int)
        dest_erp_department_id = request.form.get("dest_erp_department_id", type=int)

        if dest_erp_user_id:
            if not ResponsibleOfficial.query.filter_by(erp_user_id=dest_erp_user_id, visible=True).first():
                dest_erp_user_id = None

        if dest_erp_department_id:
            if not Department.query.filter_by(id=dest_erp_department_id, visible=True).first():
                dest_erp_department_id = None

        if not description:
            flash("Beschreibung ist ein Pflichtfeld.", "danger")
            return redirect(url_for("admin_checklists_edit", checklist_id=checklist.id))

        max_pos = (
            db.session.query(func.max(CheckListItem.position))
            .filter(CheckListItem.check_list_id == checklist.id)
            .scalar()
        )
        next_pos = (max_pos or 0) + 10

        item = CheckListItem(
            position=next_pos,
            description=description,
            sub_description=sub_description,
            ticket_subject=ticket_subject,
            ticket_content=ticket_content,
            dest_erp_user_id=dest_erp_user_id,
            dest_erp_department_id=dest_erp_department_id,
            check_list_id=checklist.id,
        )

        db.session.add(item)
        db.session.commit()
        flash("Checklisten-Item wurde angelegt.", "success")
        return redirect(url_for("admin_checklists_edit", checklist_id=checklist.id))

    @app.route("/admin/checklists/<int:checklist_id>/items/<int:item_id>/edit", methods=["POST"])
    @admin_required
    def admin_checklist_items_edit(checklist_id, item_id):
        checklist = CheckList.query.get_or_404(checklist_id)
        item = CheckListItem.query.get_or_404(item_id)

        if item.check_list_id != checklist.id:
            abort(404)

        description = (request.form.get("description") or "").strip()
        sub_description = (request.form.get("sub_description") or "").strip() or None
        ticket_subject = (request.form.get("ticket_subject") or "").strip() or None
        ticket_content = (request.form.get("ticket_content") or "").strip() or None
        dest_erp_user_id = request.form.get("dest_erp_user_id", type=int)
        dest_erp_department_id = request.form.get("dest_erp_department_id", type=int)

        if dest_erp_user_id:
            if not ResponsibleOfficial.query.filter_by(erp_user_id=dest_erp_user_id, visible=True).first():
                dest_erp_user_id = None

        if dest_erp_department_id:
            if not Department.query.filter_by(id=dest_erp_department_id, visible=True).first():
                dest_erp_department_id = None

        if not description:
            flash("Beschreibung ist ein Pflichtfeld.", "danger")
            return redirect(url_for("admin_checklists_edit", checklist_id=checklist.id))

        item.description = description
        item.sub_description = sub_description
        item.ticket_subject = ticket_subject
        item.ticket_content = ticket_content
        item.dest_erp_user_id = dest_erp_user_id
        item.dest_erp_department_id = dest_erp_department_id

        db.session.commit()
        flash("Checklisten-Item wurde aktualisiert.", "success")
        return redirect(url_for("admin_checklists_edit", checklist_id=checklist.id))

    @app.route("/admin/checklists/<int:checklist_id>/items/<int:item_id>/delete", methods=["POST"])
    @admin_required
    def admin_checklist_items_delete(checklist_id, item_id):
        checklist = CheckList.query.get_or_404(checklist_id)
        item = CheckListItem.query.get_or_404(item_id)

        if item.check_list_id != checklist.id:
            abort(404)

        db.session.delete(item)
        db.session.commit()
        flash("Checklisten-Item wurde gelöscht.", "info")
        return redirect(url_for("admin_checklists_edit", checklist_id=checklist.id))

    @app.route("/admin/checklists/<int:checklist_id>/items/<int:item_id>/move-up", methods=["POST"])
    @admin_required
    def admin_checklist_items_move_up(checklist_id, item_id):
        checklist = CheckList.query.get_or_404(checklist_id)
        item = CheckListItem.query.get_or_404(item_id)
        if item.check_list_id != checklist.id:
            abort(404)

        prev_item = (
            CheckListItem.query
            .filter(CheckListItem.check_list_id == checklist.id)
            .filter(
                (CheckListItem.position < item.position) |
                ((CheckListItem.position == item.position) & (CheckListItem.id < item.id))
            )
            .order_by(CheckListItem.position.desc(), CheckListItem.id.desc())
            .first()
        )

        if not prev_item:
            flash("Item ist bereits ganz oben.", "info")
            return redirect(url_for("admin_checklists_edit", checklist_id=checklist.id))

        item.position, prev_item.position = prev_item.position, item.position
        db.session.commit()
        flash("Item wurde nach oben verschoben.", "success")
        return redirect(url_for("admin_checklists_edit", checklist_id=checklist.id))

    @app.route("/admin/checklists/<int:checklist_id>/items/<int:item_id>/move-down", methods=["POST"])
    @admin_required
    def admin_checklist_items_move_down(checklist_id, item_id):
        checklist = CheckList.query.get_or_404(checklist_id)
        item = CheckListItem.query.get_or_404(item_id)
        if item.check_list_id != checklist.id:
            abort(404)

        next_item = (
            CheckListItem.query
            .filter(CheckListItem.check_list_id == checklist.id)
            .filter(
                (CheckListItem.position > item.position) |
                ((CheckListItem.position == item.position) & (CheckListItem.id > item.id))
            )
            .order_by(CheckListItem.position.asc(), CheckListItem.id.asc())
            .first()
        )

        if not next_item:
            flash("Item ist bereits ganz unten.", "info")
            return redirect(url_for("admin_checklists_edit", checklist_id=checklist.id))

        item.position, next_item.position = next_item.position, item.position
        db.session.commit()
        flash("Item wurde nach unten verschoben.", "success")
        return redirect(url_for("admin_checklists_edit", checklist_id=checklist.id))

    # User-Liste
    @app.route("/admin/users")
    @admin_required
    def admin_users_list():
        users = User.query.order_by(User.email.asc()).all()
        return render_template("admin/users_list.html", users=users)

    # Neuen Benutzer anlegen
    @app.route("/admin/users/create", methods=["GET", "POST"])
    @admin_required
    def admin_users_create():
        if request.method == "POST":
            email = request.form.get("email")
            name = request.form.get("name")
            password = request.form.get("password")
            is_active = bool(request.form.get("is_active"))
            is_admin = bool(request.form.get("is_admin"))
            role_id = request.form.get("role_id", type=int)

            if not email or not password:
                flash("E-Mail und Passwort sind Pflichtfelder.", "danger")
                return redirect(url_for("admin_users_create"))

            email = email.strip().lower()

            if User.query.filter_by(email=email).first():
                flash("Es existiert bereits ein Benutzer mit dieser E-Mail.", "danger")
                return redirect(url_for("admin_users_create"))

            if not role_id:
                flash("Rolle ist ein Pflichtfeld.", "danger")
                return redirect(url_for("admin_users_create"))

            role = Role.query.get(role_id)
            if not role:
                flash("Ungültige Rolle.", "danger")
                return redirect(url_for("admin_users_create"))

            # noinspection PyArgumentList
            user = User(
                email=email,
                is_active=is_active,
                is_admin=is_admin,
                name=name,
                role_id=role.id
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Benutzer wurde erstellt.", "success")
            return redirect(url_for("admin_users_list"))
        roles = Role.query.order_by(Role.name.asc()).all()
        return render_template("admin/user_form.html", user=None, roles=roles)

    @app.route("/admin/users/sync-entra", methods=["POST"])
    @admin_required
    def admin_users_sync_entra():
        try:
            results = sync_entra_users(current_app)
        except Exception as e:
            logger.error(f"admin_users_sync_entra: {str(e)}")
            flash("Entra user sync failed.", "danger")
            return redirect(url_for("admin_users_list"))

        flash(
            f"Entra user sync finished. Created: {results.get('created')}, Updated: {results.get('updated')}, "
            f"Skipped: {results.get('skipped')}, Errors: {results.get('errors')}",
            "success",
        )
        return redirect(url_for("admin_users_list"))

    # Benutzer bearbeiten
    @app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_users_edit(user_id):
        user = User.query.get_or_404(user_id)

        if request.method == "POST":
            email = request.form.get("email")
            name = request.form.get("name")
            password = request.form.get("password")  # optional
            is_active = bool(request.form.get("is_active"))
            is_admin = bool(request.form.get("is_admin"))
            role_id = request.form.get("role_id", type=int)

            if not email:
                flash("E-Mail darf nicht leer sein.", "danger")
                return redirect(url_for("admin_users_edit", user_id=user.id))

            email = email.strip().lower()

            if User.query.filter(User.email == email, User.id != user.id).first():
                flash("Es existiert bereits ein anderer Benutzer mit dieser E-Mail.", "danger")
                return redirect(url_for("admin_users_edit", user_id=user.id))

            if not role_id:
                flash("Rolle ist ein Pflichtfeld.", "danger")
                return redirect(url_for("admin_users_edit", user_id=user.id))

            role = Role.query.get(role_id)
            if not role:
                flash("Ungültige Rolle.", "danger")
                return redirect(url_for("admin_users_edit", user_id=user.id))

            user.email = email
            user.name = name
            user.is_active = is_active
            user.is_admin = is_admin
            user.role_id = role.id

            if password:
                user.set_password(password)

            db.session.commit()
            flash("Benutzer wurde aktualisiert.", "success")
            return redirect(url_for("admin_users_list"))

        roles = Role.query.order_by(Role.name.asc()).all()
        return render_template("admin/user_form.html", user=user, roles=roles)

    # Benutzer löschen
    @app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
    @admin_required
    def admin_users_delete(user_id):
        user = User.query.get_or_404(user_id)

        if user.id == current_user.id:
            flash("Du kannst dich nicht selbst löschen.", "danger")
            return redirect(url_for("admin_users_list"))

        db.session.delete(user)
        db.session.commit()
        flash("Benutzer wurde gelöscht.", "info")
        return redirect(url_for("admin_users_list"))

    @app.route("/admin/roles")
    @admin_required
    def admin_roles_list():
        roles = Role.query.order_by(Role.name.asc()).all()
        return render_template("admin/roles_list.html", roles=roles)

    @app.route("/admin/roles/create", methods=["GET", "POST"])
    @admin_required
    def admin_roles_create():
        components = ComponentCatalogItem.query.order_by(ComponentCatalogItem.name.asc()).all()

        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            component_ids = request.form.getlist("component_ids")

            if not name:
                flash("Name ist ein Pflichtfeld.", "danger")
                return redirect(url_for("admin_roles_create"))

            role = Role(name=name)
            db.session.add(role)
            db.session.flush()

            selected_components = []
            if component_ids:
                selected_components = ComponentCatalogItem.query.filter(
                    ComponentCatalogItem.id.in_(component_ids)
                ).all()
            role.components = selected_components

            db.session.commit()
            flash("Rolle wurde erstellt.", "success")
            return redirect(url_for("admin_roles_list"))

        return render_template("admin/role_form.html", role=None, components=components)

    @app.route("/admin/roles/<int:role_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_roles_edit(role_id):
        role = Role.query.get_or_404(role_id)
        components = ComponentCatalogItem.query.order_by(ComponentCatalogItem.name.asc()).all()

        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            component_ids = request.form.getlist("component_ids")

            if not name:
                flash("Name ist ein Pflichtfeld.", "danger")
                return redirect(url_for("admin_roles_edit", role_id=role.id))

            role.name = name

            selected_components = []
            if component_ids:
                selected_components = ComponentCatalogItem.query.filter(
                    ComponentCatalogItem.id.in_(component_ids)
                ).all()
            role.components = selected_components

            db.session.commit()
            flash("Rolle wurde aktualisiert.", "success")
            return redirect(url_for("admin_roles_list"))

        return render_template("admin/role_form.html", role=role, components=components)

    @app.route("/admin/roles/<int:role_id>/delete", methods=["POST"])
    @admin_required
    def admin_roles_delete(role_id):
        role = Role.query.get_or_404(role_id)

        if db.session.query(User.id).filter(User.role_id == role.id).first():
            flash("Rolle kann nicht gelöscht werden, solange Benutzer zugeordnet sind.", "danger")
            return redirect(url_for("admin_roles_list"))

        db.session.delete(role)
        db.session.commit()
        flash("Rolle wurde gelöscht.", "info")
        return redirect(url_for("admin_roles_list"))

    # -------------------------
    # FacilityCatalogItem (Ausstattungsgruppen)
    # -------------------------
    @app.route("/admin/facilities")
    @admin_required
    def admin_facilities_list():
        """List facility catalog items with search, filters and pagination."""
        # Basic query parameters for UX
        page = request.args.get("page", 1, type=int)
        q = (request.args.get("q") or "").strip()

        query = FacilityCatalogItem.query

        # Apply search filter (case-insensitive) – limited to a few fields
        if q:
            like = f"%{q}%"
            query = query.filter(
                or_(
                    FacilityCatalogItem.name.ilike(like),
                    FacilityCatalogItem.custom_name.ilike(like),
                    FacilityCatalogItem.status_name.ilike(like),
                )
            )

        # Default ordering
        query = query.order_by(FacilityCatalogItem.name.asc())

        # Pagination – moderate page size for performance
        pagination = query.paginate(page=page, per_page=25, error_out=False)
        facilities = pagination.items

        return render_template(
            "admin/facilities_list.html",
            facilities=facilities,
            pagination=pagination,
            q=q
        )

    @app.route("/admin/facilities/<int:facility_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_facilities_edit(facility_id):
        """Edit custom data of a single facility catalog item."""
        facility = FacilityCatalogItem.query.get_or_404(facility_id)

        if request.method == "POST":
            view_folded = bool(request.form.get("view_folded"))
            custom_name = request.form.get("custom_name") or None

            facility.custom_name = custom_name
            facility.view_folded = view_folded

            db.session.commit()
            flash("Ausstattungsgruppe wurde aktualisiert.", "success")
            return redirect(url_for("admin_facilities_list"))

        return render_template("admin/facility_form.html", facility=facility)

    # -------------------------
    # ComponentCatalogItem (Merkmale)
    # -------------------------
    @app.route("/admin/components")
    @admin_required
    def admin_components_list():
        """List component catalog items with search, filters and pagination."""
        page = request.args.get("page", 1, type=int)
        q = (request.args.get("q") or "").strip()
        status_filter = request.args.get("status")  # "active", "inactive" or None

        query = ComponentCatalogItem.query.join(FacilityCatalogItem, isouter=True)

        if q:
            like = f"%{q}%"
            query = query.filter(
                or_(
                    ComponentCatalogItem.name.ilike(like),
                    ComponentCatalogItem.custom_name.ilike(like),
                    ComponentCatalogItem.comment.ilike(like),
                    FacilityCatalogItem.name.ilike(like),
                    FacilityCatalogItem.custom_name.ilike(like),
                )
            )

        if status_filter == "active":
            query = query.filter(ComponentCatalogItem.enabled.is_(True))
        elif status_filter == "inactive":
            query = query.filter(ComponentCatalogItem.enabled.is_(False))

        query = query.order_by(ComponentCatalogItem.name.asc())

        pagination = query.paginate(page=page, per_page=25, error_out=False)
        components = pagination.items

        return render_template(
            "admin/components_list.html",
            components=components,
            pagination=pagination,
            q=q,
            status_filter=status_filter,
        )

    @app.route("/admin/components/<int:component_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_components_edit(component_id):
        """Edit custom data of a single component catalog item."""
        component = ComponentCatalogItem.query.get_or_404(component_id)

        if request.method == "POST":
            enabled = bool(request.form.get("enabled"))
            is_bool = bool(request.form.get("is_bool"))
            single_under_component = bool(request.form.get("single_under_component"))
            hide_quantity = bool(request.form.get("hide_quantity"))
            custom_name = request.form.get("custom_name") or None
            role_ids = request.form.getlist("role_ids")
            under_component_ids = request.form.getlist("under_component_ids")

            if is_bool and single_under_component:
                flash("Wenn bool ausgewählt wird, kann nicht zeitgleich Single Sub aktiviert sein.", category="error")
                return redirect(url_for("admin_components_list"))

            selected_under_components = []
            if under_component_ids:
                selected_under_components = UnderComponentItem.query.filter(
                    UnderComponentItem.id.in_(under_component_ids)
                ).all()

            component.enabled = enabled
            component.custom_name = custom_name
            component.is_bool = is_bool
            component.single_under_component = single_under_component
            component.hide_quantity = hide_quantity
            component.under_components = selected_under_components

            selected_roles = []
            if role_ids:
                selected_roles = Role.query.filter(Role.id.in_(role_ids)).all()
            component.roles = selected_roles

            db.session.commit()
            flash("Merkmal wurde aktualisiert.", "success")
            return redirect(url_for("admin_components_list"))

        roles = Role.query.order_by(Role.name.asc()).all()
        under_components = UnderComponentItem.query.order_by(UnderComponentItem.name.asc()).all()
        return render_template(
            "admin/component_form.html",
            component=component,
            roles=roles,
            under_components=under_components,
        )

    # -------------------------
    # UnderComponentItem (Merkmalausprägungen)
    # -------------------------
    @app.route("/admin/under_components")
    @admin_required
    def admin_under_components_list():
        """List under component items with search, filters and pagination."""
        page = request.args.get("page", 1, type=int)
        q = (request.args.get("q") or "").strip()

        query = UnderComponentItem.query

        if q:
            like = f"%{q}%"
            query = query.filter(
                or_(
                    UnderComponentItem.name.ilike(like),
                    UnderComponentItem.custom_name.ilike(like),
                )
            )

        query = query.order_by(UnderComponentItem.name.asc())

        pagination = query.paginate(page=page, per_page=25, error_out=False)
        under_components = pagination.items

        return render_template(
            "admin/under_components_list.html",
            under_components=under_components,
            pagination=pagination,
            q=q
        )

    @app.route("/admin/under_components/<int:under_component_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_under_components_edit(under_component_id):
        """Edit custom data of a single under component item."""
        under_component = UnderComponentItem.query.get_or_404(under_component_id)

        if request.method == "POST":
            custom_name = request.form.get("custom_name") or None
            component_ids = request.form.getlist("component_ids")

            selected_components = []
            if component_ids:
                selected_components = ComponentCatalogItem.query.filter(
                    ComponentCatalogItem.id.in_(component_ids)
                ).all()

            under_component.custom_name = custom_name
            under_component.components = selected_components

            db.session.commit()
            flash("Merkmalausprägung wurde aktualisiert.", "success")
            return redirect(url_for("admin_under_components_list"))

        components = ComponentCatalogItem.query.order_by(ComponentCatalogItem.name.asc()).all()
        return render_template(
            "admin/under_component_form.html",
            under_component=under_component,
            components=components,
        )

    @app.route("/admin/events")
    @admin_required
    def admin_events_list():
        cache = WowiCache(current_app.config['INI_CONFIG'].get("Wowicache", "connection_uri"))
        page = request.args.get("page", 1, type=int)
        date_from = (request.args.get("date_from") or "").strip()
        date_to = (request.args.get("date_to") or "").strip()
        user_name = (request.args.get("user_name") or "").strip()
        use_unit_idnum = (request.args.get("use_unit_idnum") or "").strip()

        query = EventItem.query

        from datetime import datetime, timedelta, time

        def parse_date(value: str):
            try:
                return datetime.strptime(value, "%Y-%m-%d").date()
            except Exception as e:
                print(str(e))
                return None

        df = parse_date(date_from) if date_from else None
        dt = parse_date(date_to) if date_to else None

        if df:
            query = query.filter(EventItem.stamp >= datetime.combine(df, time.min))
        if dt:
            query = query.filter(EventItem.stamp < datetime.combine(dt + timedelta(days=1), time.min))

        if user_name:
            query = query.filter(EventItem.user_name.ilike(f"%{user_name}%"))

        query = query.order_by(EventItem.stamp.desc(), EventItem.id.desc())

        pagination = query.paginate(page=page, per_page=50, error_out=False)
        events = pagination.items

        fac_ids = {e.facility_catalog_id for e in events if e.facility_catalog_id}
        comp_ids = {e.component_catalog_id for e in events if e.component_catalog_id}

        sub_ids = set()
        for e in events:
            if e.sub_component_ids:
                for part in str(e.sub_component_ids).split(","):
                    part = part.strip()
                    if part.isdigit():
                        sub_ids.add(int(part))

        facility_map = (
            {f.id: f.display_name for f in FacilityCatalogItem.query.filter(FacilityCatalogItem.id.in_(fac_ids)).all()}
            if fac_ids
            else {}
        )
        component_map = (
            {c.id: c.display_name for c in
             ComponentCatalogItem.query.filter(ComponentCatalogItem.id.in_(comp_ids)).all()}
            if comp_ids
            else {}
        )
        under_component_map = (
            {u.id: u.display_name for u in UnderComponentItem.query.filter(UnderComponentItem.id.in_(sub_ids)).all()}
            if sub_ids
            else {}
        )

        rows = []
        for e in events:
            sc_names = []
            if e.sub_component_ids:
                for part in str(e.sub_component_ids).split(","):
                    part = part.strip()
                    if part.isdigit():
                        sc_names.append(under_component_map.get(int(part), part))
                    elif part:
                        sc_names.append(part)
            use_unit: UseUnit
            use_unit = cache.session.query(UseUnit).filter(UseUnit.internal_id == e.use_unit_id).first()
            uu_idnum: str | None
            if use_unit:
                uu_idnum = use_unit.id_num
                if use_unit_idnum:
                    if not uu_idnum.startswith(use_unit_idnum):
                        continue
            else:
                uu_idnum = None

            rows.append(
                {
                    "stamp": e.stamp,
                    "user_name": e.user_name,
                    "action": e.action,
                    "use_unit_idnum": uu_idnum,
                    "component_name": component_map.get(e.component_catalog_id) if e.component_catalog_id else None,
                    "facility_name": facility_map.get(e.facility_catalog_id) if e.facility_catalog_id else None,
                    "sub_component_names": ", ".join(sc_names) if sc_names else None,
                }
            )

        return render_template(
            "admin/events_list.html",
            rows=rows,
            pagination=pagination,
            date_from=date_from,
            date_to=date_to,
            user_name=user_name,
            use_unit_idnum=use_unit_idnum,
        )

    @app.route("/admin/highscore")
    @admin_required
    def admin_highscore():
        date_from = (request.args.get("date_from") or "").strip()
        date_to = (request.args.get("date_to") or "").strip()

        def parse_date(value: str):
            try:
                return datetime.strptime(value, "%Y-%m-%d").date()
            except Exception as ex:
                print(str(ex))
                return None

        df = parse_date(date_from) if date_from else None
        dt = parse_date(date_to) if date_to else None

        query = EventItem.query.filter(EventItem.action.in_(["create", "edit"]))

        if df:
            query = query.filter(EventItem.stamp >= datetime.combine(df, time.min))
        if dt:
            query = query.filter(EventItem.stamp < datetime.combine(dt + timedelta(days=1), time.min))

        query = query.order_by(EventItem.user_name.asc(), EventItem.use_unit_id.asc(), EventItem.stamp.asc(),
                               EventItem.id.asc())

        cooldown = timedelta(days=7)

        points_by_user = {}
        last_scored = {}

        for e in query.yield_per(2000):
            if not e.user_name:
                continue
            if not e.use_unit_id:
                continue

            user_key = e.user_name
            unit_key = e.use_unit_id
            t = e.stamp

            if t is None:
                continue

            user_units = last_scored.get(user_key)
            if user_units is None:
                user_units = {}
                last_scored[user_key] = user_units

            last_time = user_units.get(unit_key)
            if last_time is None or t >= last_time + cooldown:
                points_by_user[user_key] = points_by_user.get(user_key, 0) + 1
                user_units[unit_key] = t

        top = sorted(points_by_user.items(), key=lambda x: (-x[1], x[0]))[:10]
        rows = [{"rank": i + 1, "user_name": u, "points": p} for i, (u, p) in enumerate(top)]

        return render_template(
            "admin/highscore.html",
            rows=rows,
            date_from=date_from,
            date_to=date_to,
        )
