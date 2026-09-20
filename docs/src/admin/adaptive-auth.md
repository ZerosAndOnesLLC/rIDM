# Adaptive authentication

Risk-based adaptive authentication scores every sign-in against what the user has done
before, and lets the tenant decide what an unusual one costs: nothing, a second factor,
or a refusal. It is off until an administrator turns it on, and it changes nothing
about how correct credentials are checked — a wrong password is still a wrong password.

All of it is tenant configuration: Settings → Adaptive auth in the console, or
`PATCH /admin/tenants/{slug}` with `ridm:tenants:write` (see
[Tenants and tenant settings](tenants.md)). The location signals additionally need a
geo source on the deployment, which is operator configuration
([Geo-IP](../reference/configuration.md#geo-ip)).

## The signals

Each signal a sign-in raises adds its weight to the score.

| Signal | Raised when | Needs |
|--------|-------------|-------|
| `new_device` | The browser sent no live trusted-device cookie and the user has signed in before, but never from this user agent | Nothing |
| `new_country` | The user has never signed in from this country before | A geo source |
| `impossible_travel` | The distance from where the user was last seen cannot be covered in the time since, at `impossible_travel_kmh` | A geo source that yields coordinates |
| `velocity` | The address is behind `velocity_max_failures` or more failed sign-ins in the last `velocity_window_minutes` | Nothing |

A signal that cannot be computed is not raised. A user's very first sign-in raises
nothing at all: there is no history to be unlike. This is deliberate, and it is why
turning the policy on does not step up every user at once — the history fills in as
people sign in.

Two points less than 100 km apart never count as travel (city coordinates move around
without the user doing so), and a sign-in whose country is known but whose coordinates
are not can still raise `new_country`.

## The score and the two thresholds

```json
{
  "settings": {
    "risk": {
      "enabled": true,
      "weights": { "new_device": 20, "new_country": 50, "impossible_travel": 60, "velocity": 40 },
      "step_up_at": 50,
      "block_at": 100,
      "impossible_travel_kmh": 900,
      "velocity_window_minutes": 15,
      "velocity_max_failures": 10
    }
  }
}
```

| Score | Outcome |
|-------|---------|
| Below `step_up_at` | Nothing: the sign-in proceeds as it always would |
| `step_up_at` or above | **Step up.** The sign-in must pass a second factor |
| `block_at` or above | **Block.** The sign-in is refused |

Either threshold at `0` switches that outcome off: `block_at: 0` runs the policy in
step-up-only mode, and both at `0` scores sign-ins without ever acting on them (useful
while tuning, since the score still reaches the audit log the moment either threshold
is crossed — set them high rather than to zero if you want to watch first).

With the defaults above, a new country alone steps up; a new country from a new browser
after impossible travel blocks.

### What a step-up does

The second factor is demanded for that sign-in whatever `settings.mfa` says, and
**a trusted-device cookie does not waive it**: the cookie says which browser this is,
not who is holding it. A user with no second factor enrols one then and there, exactly
as under `mfa.mode: "required"` — so a tenant that blocks or steps up should offer at
least one factor under Settings → Sign-in.

### What a block does

The flow ends: no session is opened (or, on a resumed session, none is usable for this
request), the login flow is discarded, and the browser goes back to the client with
`error=access_denied`. A device-code approval is denied so the waiting device stops
polling. The attempt is written to the login-attempt log as a failure with the reason
`risk_blocked`, which also feeds the velocity signal — a run of blocked attempts from
one address raises it.

A blocked sign-in teaches the history nothing: its country does not become a place the
user is known to sign in from.

## When a sign-in is scored

Twice:

1. **When a first factor passes** — password, passwordless code, magic link, passkey,
   registration, or a brokered sign-in from an upstream provider. The score is decided
   once and carried for the rest of the flow.
2. **When a live session is reused** at `/authorize` or at a device-code approval. A
   session that opened somewhere safe can be used from anywhere, so a silent sign-in
   from a new country steps up, and one the policy blocks answers `access_denied`.
   The session is the browser's own history, so `new_device` never fires on this path.

Personal access tokens, client credentials and refresh-token exchanges are not sign-ins
and are not scored.

## Where the history comes from

A sign-in the policy allows records the country it came from (and its coordinates, when
the source has them) against the user. Nothing is recorded while the policy is off, and
the rows go with the user when the account is deleted. Each row holds the country, the
last coordinates seen in it, a count and the first and last times it was seen.

## In the audit log

A step-up and a block each write one event; an ordinary sign-in writes none.

| Event | Payload |
|-------|---------|
| `risk.step_up` | `user_id`, `score`, `signals`, `country` |
| `risk.blocked` | `user_id`, `score`, `signals`, `country` |

Both carry the request's address and user agent like every other event, and both reach
webhooks subscribed to `risk.*`. See [Webhooks and the audit log](webhooks-audit.md).

The `ridm_risk_decisions_total` counter (labelled `action`) tracks the same two
outcomes for dashboards.

## Turning it on safely

1. Configure a geo source, unless you only want the device and velocity signals.
2. Make sure at least one second-factor method is enabled.
3. Start with `block_at: 0`, so the worst that happens is a second factor.
4. Watch `risk.step_up` in the audit log for a week; the history is filling in during
   that time, so expect more step-ups early on than later.
5. Lower `block_at` into place once the signals look right for your users.
