import click
from app.extensions import db
from app.models import User
from app.geo import update_geolocation, get_buildings_in_radius_m
from app.erp import sync_erp_data
from app.entra_sync import sync_entra_users


def register_cli_commands(app):

    @app.cli.command("create-user")
    @click.option("--email", prompt=True, help="Email address of the new user")
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True,
                  help="Password of the new user")
    @click.option("--admin", prompt=True, help="Is this an administrator?", default=False)
    def create_user(email, password, admin):
        existing = User.query.filter_by(email=email).first()
        if existing:
            click.echo(f"User '{email}' already exists.")
            return

        # noinspection PyArgumentList
        user = User(email=email)
        user.set_password(password)
        user.is_admin = bool(admin)
        db.session.add(user)
        db.session.commit()

        click.echo(f"User '{email}' created successfully.")

    @app.cli.command("disable-user")
    @click.option("--email", prompt=True, help="Email address of the user")
    def disable_user(email):
        existing = User.query.filter_by(email=email).first()
        if not existing:
            click.echo(f"User '{email}' does not exist.")
            return

        user = db.session.query(User).filter(User.email == email).first()
        user.is_active = False
        db.session.commit()

        click.echo(f"User '{email}' disabled and logged out.")

    @app.cli.command("enable-user")
    @click.option("--email", prompt=True, help="Email address of the user")
    def enable_user(email):
        existing = User.query.filter_by(email=email).first()
        if not existing:
            click.echo(f"User '{email}' does not exist.")
            return

        user = db.session.query(User).filter(User.email == email).first()
        user.is_active = True
        db.session.commit()

        click.echo(f"User '{email}' enabled.")

    @app.cli.command("geo-update")
    def geo_update():
        update_geolocation(False)

    @app.cli.command("test-geo-radius")
    @click.option("--lat", prompt=True)
    @click.option("--lon", prompt=True)
    @click.option("--radius", prompt=True)
    def test_radius(lat, lon, radius):
        radius = float(radius)

        results = get_buildings_in_radius_m(lat, lon, radius)

        click.echo(f"Found buildings in radius {radius} km:")
        for r in results:
            click.echo(f"- {r['building_idnum']} ({r['lat']}, {r['lon']}) -> {r['distance_m']} m")

    @app.cli.command("sync-erp")
    def cli_sync_erp():
        results = sync_erp_data()

        click.echo(f"Result: {results}")

    @app.cli.command("sync-entra-users")
    def cli_sync_entra_users():
        results = sync_entra_users(app)
        click.echo(f"Result: {results}")
