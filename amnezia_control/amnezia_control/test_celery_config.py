from django.test import SimpleTestCase

from .celery import app


class CeleryConfigurationTest(SimpleTestCase):
    def test_broker_retry_on_startup_is_explicitly_enabled(self):
        self.assertIs(
            app.conf.broker_connection_retry_on_startup,
            True,
        )
