# SPDX-License-Identifier: AGPL-3.0-only
"""The web tests start the app in demo mode; they expect an empty store, so the demo sample data is off."""
import os

os.environ.setdefault("WDT_DEMO_SEED", "false")
