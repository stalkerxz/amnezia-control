.PHONY: up down logs migrate superuser seed test
up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f web worker

migrate:
	docker compose exec web python manage.py migrate

superuser:
	docker compose exec web python manage.py createsuperuser

seed:
	docker compose exec web python manage.py seed_demo

test:
	docker compose exec web python manage.py test
