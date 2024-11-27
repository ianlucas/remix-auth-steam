/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Ian Lucas. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { redirect, SessionStorage } from "@remix-run/server-runtime";
import OpenID from "openid";
import { AuthenticateOptions, Strategy, StrategyVerifyCallback } from "remix-auth";
import SteamAPI, { UserSummary } from "steamapi";

export interface SteamStrategyOptions {
    apiKey: string;
    onError?: (error: unknown) => void;
    realm?: string;
    returnURL: string;
}

export type SteamStrategyVerifyParams = {
    request: Request;
    user: UserSummary;
};

function authenticateToSteam(relyingParty: OpenID.RelyingParty): Promise<string> {
    return new Promise((resolve, reject) => {
        relyingParty.authenticate("https://steamcommunity.com/openid", false, (err, url) => {
            if (err) {
                return reject(err);
            }
            if (!url) {
                return reject("Got no URL from authenticate method");
            }
            return resolve(url);
        });
    });
}

function verifySteamAssertion(
    relyingParty: OpenID.RelyingParty,
    request: Request
): Promise<{
    authenticated: boolean;
    claimedIdentifier?: string | undefined;
}> {
    return new Promise((resolve, reject) => {
        relyingParty.verifyAssertion(request, (err, result) => {
            if (err) {
                return reject(err);
            }
            if (!result) {
                return reject("No result from verifyAssertion");
            }
            return resolve(result);
        });
    });
}

export class SteamStrategy<User> extends Strategy<User, SteamStrategyVerifyParams> {
    name = "steam";

    constructor(
        private options: SteamStrategyOptions | ((request: Request) => Promise<SteamStrategyOptions>),
        verify: StrategyVerifyCallback<User, SteamStrategyVerifyParams>
    ) {
        super(verify);
    }

    async authenticate(request: Request, sessionStorage: SessionStorage, options: AuthenticateOptions): Promise<User> {
        const { apiKey, onError, returnURL, realm } =
            typeof this.options === "function" ? await this.options(request) : this.options;
        const notifyError = (error: unknown) => {
            if (!(error instanceof Response)) {
                onError?.(error);
            }
        };
        try {
            const relyingParty = new OpenID.RelyingParty(returnURL, realm ?? null, true, false, []);
            const steamApi = new SteamAPI(apiKey);
            const url = new URL(request.url);
            const callbackUrl = new URL(returnURL);
            if (url.pathname === callbackUrl.pathname) {
                const result = await verifySteamAssertion(relyingParty, request);
                if (!result.authenticated || !result.claimedIdentifier)
                    return this.failure("Not authenticated from result", request, sessionStorage, options);
                try {
                    const userSteamID = result.claimedIdentifier.toString().split("/").at(-1);
                    if (userSteamID === undefined) {
                        throw new Error("Unable to get SteamID.");
                    }
                    const steamUserSummary = (await steamApi.getUserSummary(userSteamID)) as UserSummary;
                    const user = await this.verify({ user: steamUserSummary, request });
                    return this.success(user, request, sessionStorage, options);
                } catch (error) {
                    notifyError(error);
                    let message = (error as Error).message;
                    return this.failure(message, request, sessionStorage, options);
                }
            } else {
                try {
                    throw redirect(await authenticateToSteam(relyingParty));
                } catch (error) {
                    notifyError(error);
                    throw error;
                }
            }
        } catch (error) {
            notifyError(error);
            throw error;
        }
    }
}
