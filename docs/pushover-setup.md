# Slink Pushover Setup Guide

Slink uses Pushover to deliver real-time push notifications to phones and desktops. This guide covers how to add new users to Slink's alert pipeline.

## How It Works

Slink sends to a single Pushover "user key" stored in its `.env` file. That key can be either:

- **An individual user key** — alerts go to one person
- **A Delivery Group key** — alerts go to everyone in the group (recommended for teams)

Using a Delivery Group means adding/removing users doesn't require touching Slink's config. The admin manages membership in Pushover's dashboard, and Slink keeps sending to the same group key.

## Alert Levels

Slink maps detection severity to Pushover priority:

| Slink Severity | Pushover Priority | Behavior |
|----------------|------------------|----------|
| **Emergency** (AI-triaged incident match) | **Priority 2** — Emergency | Repeats every 3 min until acknowledged on phone. Alarm sound. Bypasses Do Not Disturb. |
| **Critical / High** | **Priority 1** — High | Bypasses quiet hours. Siren sound. |
| **Medium** (batch digest, every 15 min) | **Priority 0** — Normal | Standard notification. |
| **Low** (health alerts) | **Priority -1** — Low | No sound or vibration, badge only. |

## For New Users: Getting Set Up

### 1. Create a Pushover Account

1. Go to [pushover.net](https://pushover.net) and create an account ($5 one-time per platform after 30-day trial).
2. Note your **User Key** displayed on the dashboard — it looks like `u1234abcd5678efgh`.

### 2. Install the App

Install Pushover on the device(s) you want alerts on:

- **iOS**: [App Store](https://apps.apple.com/app/pushover-notifications/id506088175)
- **Android**: [Google Play](https://play.google.com/store/apps/details?id=net.superblock.pushover)
- **Desktop**: [pushover.net/clients](https://pushover.net/clients) (Mac, Windows, browser)

### 3. Log In and Verify

Open the app, log in, and send yourself a test notification from the Pushover dashboard to confirm delivery works.

### 4. Send Your User Key to the Slink Admin

Give the admin your **User Key** (from [pushover.net](https://pushover.net) dashboard, top right). They'll add you to the delivery group.

### 5. Configure Quiet Hours (Optional)

In the Pushover app settings, you can set quiet hours. Note that **Critical/High** alerts (Priority 1) and **Emergency** alerts (Priority 2) bypass quiet hours by design — this is intentional so incident-level threats always wake you up.

## For Admins: Adding Users to Slink Alerts

### Option A: Using a Delivery Group (Recommended)

This is the best approach for teams. One-time setup, then add/remove users without restarting Slink.

#### Initial Setup (One Time)

1. Log into [pushover.net](https://pushover.net) as the Slink admin account.
2. Go to **Groups** (left sidebar) → **Create a Delivery Group**.
3. Name it something like `Slink Alerts`.
4. Copy the **Group Key** — it begins with `g...`.
5. Set this as `PUSHOVER_USER_KEY` in Slink's `.env`:
   ```
   PUSHOVER_USER_KEY=<your-group-key>
   ```
6. Restart Slink: `docker compose down && docker compose up -d`

#### Adding a New User

1. Get the new user's **User Key** (they get this from step 4 above).
2. In [pushover.net](https://pushover.net) → **Groups** → **Slink Alerts**.
3. Paste their User Key into "Add User" and click **Add**.
4. **No Slink restart needed** — the next alert automatically goes to all group members.

#### Removing a User

1. In [pushover.net](https://pushover.net) → **Groups** → **Slink Alerts**.
2. Click **Remove** next to the user.
3. Immediate — no restart needed.

### Option B: Single User Key (Current Setup)

If only one person needs alerts, set their individual User Key directly:

```
PUSHOVER_USER_KEY=<your-user-key>
```

To switch to a different person, change the key and restart Slink.

### Application Token

The `PUSHOVER_API_TOKEN` is the application token registered to "Slink" in Pushover. This is set once and doesn't change when adding users. If you need to create a new one:

1. Go to [pushover.net/apps](https://pushover.net/apps) → **Create New Application**.
2. Name: `Slink`, Type: `Script/Shell`, Description: `Threat intelligence alerts`.
3. Copy the **API Token** and set it in `.env`:
   ```
   PUSHOVER_API_TOKEN=<your-app-token>
   ```

## Verifying the Setup

After adding a user, there's no safe way to trigger a test from Slink without sending a real-looking alert to Teams. Instead:

1. **Pushover dashboard test**: From [pushover.net](https://pushover.net), use the built-in "Send a Notification" form to verify the user's device is receiving.
2. **Wait for the next real alert**: Slink fires medium-severity batch digests every 15 minutes when new detections exist. The new user should receive these.
3. **Check Slink logs**: After a detection fires, look for `Pushover notification sent` or `EMERGENCY Pushover sent` in the API logs:
   ```bash
   docker compose logs api | grep -i pushover
   ```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| User not receiving alerts | Verify their User Key is correct and they're in the Delivery Group |
| "Pushover not configured" in logs | `PUSHOVER_API_TOKEN` or `PUSHOVER_USER_KEY` is empty in `.env` |
| Emergency alerts not repeating | Priority 2 requires the user to acknowledge in the app — check the app |
| Alerts arriving but no sound | Check device notification settings and Pushover app permissions |
| User gets health alerts but not emergencies | Shouldn't happen — all alert types go to the same key. Check Slink logs for errors |
