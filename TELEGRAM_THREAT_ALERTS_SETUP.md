# Telegram threat-alert integration

## Actual event path
The dashboard processes completed scanner results through `process_alerts()`.
Eligible HIGH/CRITICAL risk or supported novelty findings are persisted to
`alert_history.csv` and dispatched via `NotificationManager.notify_threat()`.
Telegram delivery is tied to those detections, not merely to dashboard refreshes.

## Windows setup
Revoke any token previously exposed and use a newly generated BotFather token.
Save the new token and numeric chat ID with PowerShell:

```powershell
[Environment]::SetEnvironmentVariable("SENTINELSHIELD_TELEGRAM_BOT_TOKEN", "PASTE_NEW_TOKEN_HERE", "User")
[Environment]::SetEnvironmentVariable("SENTINELSHIELD_TELEGRAM_CHAT_ID", "YOUR_NUMERIC_CHAT_ID", "User")
```

The notification manager reads the process environment first and, on Windows,
falls back to the current user's environment registry. This helps when the
running shell has not refreshed its environment after saving settings.

## Test
1. Open Telegram, open your bot, press Start, and send it a message.
2. From this project folder run `python -m streamlit run dashboard.py`.
3. Use the dashboard's **Trigger test alert** button.
4. Then perform an authorized scan and verify that a HIGH/CRITICAL detection
   creates an alert and sends the Telegram message.

Notifications follow the dashboard's alert toggles and the configured cooldown
(120 seconds by default). Missing credentials or network errors should not stop
scanning. Never test rogue access points on networks without authorization.
