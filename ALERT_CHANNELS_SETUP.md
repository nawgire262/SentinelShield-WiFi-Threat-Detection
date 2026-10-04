# Alert channels

Desktop alerts are enabled by default for HIGH and CRITICAL scan results. They
are rate-limited per SSID/BSSID (120 seconds by default) so a noisy access point
does not flood the user or block a scan.

Remote channels are optional. Copy the variable names in `.env.example` into
Windows user environment variables, then restart Streamlit/scanner:

```powershell
[Environment]::SetEnvironmentVariable('SENTINELSHIELD_TELEGRAM_BOT_TOKEN', 'your-token', 'User')
[Environment]::SetEnvironmentVariable('SENTINELSHIELD_TELEGRAM_CHAT_ID', 'your-chat-id', 'User')
```

For email configure the `SENTINELSHIELD_SMTP_*` variables; use an app password,
not an account password. SMS uses Twilio and requires all `SENTINELSHIELD_TWILIO_*`
variables plus `SENTINELSHIELD_SMS_TO`. With no credentials configured, those
channels remain disabled and scans continue normally.

To test desktop alerts after starting the project environment:

```powershell
python -c "from notification_manager import NotificationManager; print(NotificationManager().notify_threat('SentinelShield-Test','00:00:00:00:00:01',85,'Notification test'))"
```
