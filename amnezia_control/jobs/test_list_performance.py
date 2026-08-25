from unittest.mock import patch

from django.contrib.auth import (
    get_user_model,
)
from django.db import connection
from django.http import HttpResponse
from django.test import (
    RequestFactory,
    TestCase,
)
from django.test.utils import (
    CaptureQueriesContext,
)

from servers.models import Server

from .models import (
    Job,
    JobEvent,
)
from .views import jobs_list_view


class JobsListPerformanceTests(TestCase):
    def setUp(self):
        self.user = (
            get_user_model()
            .objects.create_user(
                "perf-admin",
                password="123",
                is_staff=True,
            )
        )

        self.server = (
            Server.objects.create(
                name="perf-server"
            )
        )

        self.factory = (
            RequestFactory()
        )

    def _request(self, params=None):
        request = self.factory.get(
            "/jobs/",
            params or {},
        )

        request.user = self.user

        return request

    def test_jobs_list_does_not_query_events_per_job(
        self,
    ):
        jobs = [
            Job(
                server=self.server,
                actor=self.user,
                action=f"job-{index}",
                status=Job.Status.SUCCESS,
            )
            for index in range(120)
        ]

        Job.objects.bulk_create(
            jobs
        )

        saved_jobs = list(
            Job.objects.order_by("id")
        )

        JobEvent.objects.bulk_create(
            [
                JobEvent(
                    job=job,
                    level="info",
                    message="done",
                )
                for job in saved_jobs
            ]
        )

        request = self._request()

        with patch(
            "jobs.views.render",
            return_value=HttpResponse(
                "ok"
            ),
        ):
            with CaptureQueriesContext(
                connection
            ) as queries:
                response = (
                    jobs_list_view(
                        request
                    )
                )

        self.assertEqual(
            response.status_code,
            200,
        )

        # Expected shape:
        # count + page + event prefetch.
        # Leave one query of tolerance
        # for backend/version differences.
        self.assertLessEqual(
            len(queries),
            4,
        )

    def test_signal_filters_keep_classifier_semantics(
        self,
    ):
        degraded = Job.objects.create(
            server=self.server,
            actor=self.user,
            action="degraded",
            status=Job.Status.SUCCESS,
        )

        JobEvent.objects.create(
            job=degraded,
            level="warning",
            message=(
                "runtime telemetry "
                "unavailable: degraded"
            ),
        )

        warning = Job.objects.create(
            server=self.server,
            actor=self.user,
            action="warning",
            status=Job.Status.SUCCESS,
        )

        JobEvent.objects.create(
            job=warning,
            level="warning",
            message="manual warning",
        )

        regular = Job.objects.create(
            server=self.server,
            actor=self.user,
            action="regular",
            status=Job.Status.SUCCESS,
        )

        captured = {}

        def capture_render(
            request,
            template_name,
            context,
            *args,
            **kwargs,
        ):
            captured["rows"] = [
                row["job"].action
                for row in context[
                    "job_rows"
                ]
            ]

            return HttpResponse("ok")

        request = self._request(
            {
                "signal":
                    "degraded_success"
            }
        )

        with patch(
            "jobs.views.render",
            side_effect=capture_render,
        ):
            jobs_list_view(request)

        self.assertEqual(
            captured["rows"],
            ["degraded"],
        )

        request = self._request(
            {
                "signal":
                    "warning"
            }
        )

        with patch(
            "jobs.views.render",
            side_effect=capture_render,
        ):
            jobs_list_view(request)

        self.assertEqual(
            captured["rows"],
            ["warning"],
        )

        request = self._request(
            {
                "signal":
                    "success"
            }
        )

        with patch(
            "jobs.views.render",
            side_effect=capture_render,
        ):
            jobs_list_view(request)

        self.assertEqual(
            captured["rows"],
            ["regular"],
        )
