"""Tests for server-owned MikroTik onboarding sessions."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from accounts.models import Organization
from core import wireguard
from core.mikrotik_onboarding import (
    OnboardingError,
    commit_session,
    issue_session_token,
    load_open_session,
    sync_session_from_tunnel_payload,
)
from core.models import MikroTikOnboardingSession, MikroTikRouter, WireGuardReservation

User = get_user_model()


class OnboardingSessionTokenTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("owner", password="x")
        self.org = Organization.objects.create(
            name="Test ISP",
            owner=self.user,
            join_code="111111",
        )
        self.session = MikroTikOnboardingSession.objects.create(
            organization=self.org,
            initiated_by=self.user,
            label="Site A",
            tunnel_address="10.9.0.50",
            planned_lan="192.168.12.1",
            management_host="192.168.12.1",
            verified_dial_host="192.168.12.1",
            username="admin",
            password="secret",
            serial_number="SN123",
            software_id="SW456",
            phase=MikroTikOnboardingSession.Phase.PREPARED,
            expires_at=timezone.now() + timedelta(hours=4),
        )

    def test_issue_and_load_session_token(self):
        token = issue_session_token(self.session)
        loaded = load_open_session(token, organization=self.org, user=self.user)
        self.assertEqual(loaded.pk, self.session.pk)

    def test_sync_tunnel_ready_updates_phase(self):
        sync_session_from_tunnel_payload(
            self.session,
            {"ready": True, "lan_address": "192.168.12.1", "address": "10.9.0.50"},
        )
        self.session.refresh_from_db()
        self.assertEqual(
            self.session.phase, MikroTikOnboardingSession.Phase.TUNNEL_READY
        )

    @patch("core.mikrotik_connect.configure_mikrotik_wifi")
    @patch("core.mikrotik_jobs.schedule_post_onboard_nas_refresh")
    @patch("accounts.communications.dispatch_platform_event")
    @patch("accounts.communications.dispatch_org_event")
    @patch("core.mikrotik_onboarding.wireguard.adopt_reservation_for_router")
    def test_commit_uses_session_management_host(
        self,
        adopt_mock,
        _org_event,
        _plat_event,
        _nas,
        _wifi,
    ):
        adopt_mock.return_value = True
        reservation = WireGuardReservation.objects.create(
            organization=self.org,
            label="Site A",
            address="10.9.0.50",
            lan_address="192.168.88.1",
            public_key="x" * 44,
            private_key="y" * 44,
        )
        self.session.reservation = reservation
        self.session.management_host = "192.168.0.112"
        self.session.verified_dial_host = "192.168.0.112"
        self.session.phase = MikroTikOnboardingSession.Phase.AUTHENTICATED
        self.session.authenticated_at = timezone.now()
        self.session.save()

        class _Req:
            user = self.user
            POST = {}

        from core.forms import MikroTikOnboardForm

        form = MikroTikOnboardForm(
            {
                "name": "Router One",
                "model": MikroTikRouter.ModelChoice.OTHER,
                "location": "Nairobi",
                "host": "192.168.0.112",
                "username": "admin",
                "password": "secret",
            }
        )
        self.assertTrue(form.is_valid(), form.errors)
        result = commit_session(self.session, form, organization=self.org, request=_Req())
        router = result.router
        self.assertEqual(router.host, "192.168.0.112")
        self.assertEqual(router.vpn_address, "10.9.0.50")
        adopt_mock.assert_called_once()
        saved = MikroTikRouter.objects.get(pk=router.pk)
        self.assertEqual(saved.serial_number, "SN123")


class PrepareSessionCleanupTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("owner2", password="x")
        self.org = Organization.objects.create(
            name="Cleanup ISP",
            owner=self.user,
            join_code="333333",
        )
        self.reservation = WireGuardReservation.objects.create(
            organization=self.org,
            label="Site",
            address="10.9.0.60",
            lan_address="192.168.20.1",
            public_key="c" * 44,
            private_key="d" * 44,
        )

    def test_prepare_cancels_duplicate_open_sessions(self):
        from core.mikrotik_onboarding import prepare_onboarding_session
        from core.models import MikroTikOnboardingSession

        first = prepare_onboarding_session(
            self.reservation,
            organization=self.org,
            user=self.user,
            label="Site",
        )
        second = prepare_onboarding_session(
            self.reservation,
            organization=self.org,
            user=self.user,
            label="Site",
        )
        first.refresh_from_db()
        self.assertEqual(first.phase, MikroTikOnboardingSession.Phase.CANCELLED)
        self.assertEqual(second.phase, MikroTikOnboardingSession.Phase.PREPARED)
        open_count = MikroTikOnboardingSession.objects.filter(
            organization=self.org,
            reservation=self.reservation,
            phase=MikroTikOnboardingSession.Phase.PREPARED,
        ).count()
        self.assertEqual(open_count, 1)


class PurgeReservationSessionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("owner3", password="x")
        self.org = Organization.objects.create(
            name="Purge ISP",
            owner=self.user,
            join_code="444444",
        )

    @patch("core.wireguard.can_apply_server_peers", return_value=False)
    @patch("core.wireguard.remove_server_peer", return_value={"ok": True})
    @patch("core.wireguard.inspect_server_peer", return_value={"checked": False})
    @patch("core.wireguard.reservation_connect_is_stale", return_value=True)
    @patch("core.wireguard._reservation_purge_enabled", return_value=True)
    def test_purge_cancels_linked_sessions(self, *_mocks):
        from core.models import MikroTikOnboardingSession

        reservation = WireGuardReservation.objects.create(
            organization=self.org,
            label="Old",
            address="10.9.0.61",
            lan_address="192.168.21.1",
            public_key="e" * 44,
            private_key="f" * 44,
        )
        session = MikroTikOnboardingSession.objects.create(
            organization=self.org,
            initiated_by=self.user,
            reservation=reservation,
            label="Old",
            tunnel_address=reservation.address,
            phase=MikroTikOnboardingSession.Phase.TUNNEL_READY,
            expires_at=timezone.now() + timedelta(hours=4),
        )
        wireguard.purge_stale_wireguard_reservations(
            keep_labels=set(),
            organization=self.org,
        )
        session.refresh_from_db()
        self.assertEqual(session.phase, MikroTikOnboardingSession.Phase.CANCELLED)
        self.assertFalse(WireGuardReservation.objects.filter(pk=reservation.pk).exists())


class AdoptReservationHostTests(TestCase):
    def test_adopt_does_not_overwrite_verified_lan(self):
        reservation = WireGuardReservation.objects.create(
            organization=Organization.objects.create(
                name="O",
                owner=User.objects.create_user("u2", password="x"),
                join_code="222222",
            ),
            label="R",
            address="10.9.0.3",
            lan_address="192.168.12.1",
            public_key="a" * 44,
            private_key="b" * 44,
        )
        router = MikroTikRouter.objects.create(
            organization=reservation.organization,
            name="R",
            host="192.168.0.99",
            vpn_address="10.9.0.3",
            username="admin",
            password="x",
        )
        wireguard.adopt_reservation_for_router(router)
        router.refresh_from_db()
        self.assertEqual(router.host, "192.168.0.99")


class OnboardConnectAuthCooldownTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("owner2", password="x")
        self.org = Organization.objects.create(
            name="Test ISP 2",
            owner=self.user,
            join_code="333333",
        )
        self.session = MikroTikOnboardingSession.objects.create(
            organization=self.org,
            initiated_by=self.user,
            label="Site B",
            tunnel_address="10.9.0.7",
            phase=MikroTikOnboardingSession.Phase.PREPARED,
            expires_at=timezone.now() + timedelta(hours=4),
        )

    @patch("core.mikrotik_connect.test_mikrotik_api_login")
    def test_auth_failure_triggers_cooldown(self, mock_login):
        from core.mikrotik_connect import (
            clear_onboard_connect_auth_cooldown,
            is_onboard_connect_auth_cooling_down,
        )
        from core.mikrotik_onboarding import authenticate_connect

        mock_login.return_value = {
            "ok": False,
            "auth_error": True,
            "error": "invalid user name or password",
        }
        clear_onboard_connect_auth_cooldown("192.168.88.1", self.org.pk)
        first = authenticate_connect(
            self.session,
            host="192.168.88.1",
            username="admin",
            password="wrong",
            organization=self.org,
        )
        self.assertFalse(first["ok"])
        self.assertTrue(first.get("auth_error"))
        self.assertTrue(
            is_onboard_connect_auth_cooling_down("192.168.88.1", self.org.pk)
        )
        second = authenticate_connect(
            self.session,
            host="192.168.88.1",
            username="admin",
            password="wrong",
            organization=self.org,
        )
        self.assertTrue(second.get("cooling_down"))
        self.assertEqual(mock_login.call_count, 1)
