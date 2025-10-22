# remix-auth-steam

> A Steam strategy for Remix Auth library

## Install

```bash
npm install @ianlucas/remix-auth-steam
```

## Usage

### Adding it to Remix Auth

```typescript
import { SteamStrategy as BaseSteamStrategy } from "@ianlucas/remix-auth-steam";
import { Strategy } from "remix-auth/strategy";
import SteamAPI, { type UserSummary } from "steamapi";

class SteamStrategy extends BaseSteamStrategy<string> {
    constructor() {
        super(
            async () => ({
                returnURL: STEAM_CALLBACK_URL
            }),
            async ({ userID }) =>
                await upsertUser((await new SteamAPI(STEAM_API_KEY).getUserSummary(userID)) as UserSummary)
        );
    }
}

export const authenticator = new Authenticator<string>();
authenticator.use(new SteamStrategy(), "steam");
```

### Using it in routes

#### `sign-in._index.tsx`

```typescript
export async function loader({ request }: Route.LoaderArgs) {
    return authenticator.authenticate("steam", request);
}
```

#### `sign-in.steam.callback._index.tsx`

```typescript
export async function loader({ request }: Route.LoaderArgs) {
    const userId = await authenticator.authenticate("steam", request);
    const session = await getSession(request.headers.get("cookie"));
    session.set("userId", userId);
    throw redirect("/", {
        headers: {
            "Set-Cookie": await commitSession(session)
        }
    });
}
```
