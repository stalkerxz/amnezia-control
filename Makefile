.PHONY: up up-proxy down logs migrate superuser seed seed-demo-admin test
up:
	docker compose up -d --build

up-proxy:
	docker compose -f docker-compose.yml -f docker-compose.proxy.yml up -d --build

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

seed-demo-admin:
	docker compose exec web python manage.py seed_demo --with-demo-admin

test:
	docker compose exec web python manage.py test
