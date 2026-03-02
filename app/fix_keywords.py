# reseed_keywords.py
"""
Delete cfg_risky_terms2 (and legacy cfg_risky_terms) so the app
re-seeds the default keyword library on next run.
It also triggers reseeding immediately so you don't have to restart.
"""

from app import app, get_db, ensure_default_parameters, cfg_get

def reseed():
    with app.app_context():
        db = get_db()
        # Remove both the new and legacy keys
        db.execute("DELETE FROM config_kv WHERE key IN ('cfg_risky_terms2','cfg_risky_terms')")
        db.commit()

        # Re-seed defaults (this is the same logic as app startup)
        ensure_default_parameters()

        # Show what’s now stored
        val = cfg_get("cfg_risky_terms2", [], list)
        print("✅ Reseeded cfg_risky_terms2 ->", val)

if __name__ == "__main__":
    reseed()