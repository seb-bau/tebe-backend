from app.app import create_app
from app.celery_app import celery, init_celery
from app.tasks import register_tasks

flask_app = create_app()
init_celery(flask_app)
register_tasks(celery)
