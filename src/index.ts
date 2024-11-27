/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Ian Lucas. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import OpenID from "openid";
import { redirect } from "react-router";
import { Strategy } from "remix-auth/strategy";
import SteamAPI, { type UserSummary } from "steamapi";

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
    return new Promise((resolve, reject) =>
        relyingParty.authenticate("https://steamcommunity.com/openid", false, (err, url) => {
            if (err) {
                return reject(err);
            }
            if (!url) {
                return reject("Got no URL from authenticate method");
            }
            return resolve(url);
        })
    );
}

function verifySteamAssertion(
    relyingParty: OpenID.RelyingParty,
    request: Request
): Promise<{
    authenticated: boolean;
    claimedIdentifier?: string | undefined;
}> {
    return new Promise((resolve, reject) =>
        relyingParty.verifyAssertion(request, (err, result) => {
            if (err) {
                return reject(err);
            }
            if (!result) {
                return reject("No result from verifyAssertion");
            }
            return resolve(result);
        })
    );
}

export class SteamStrategy<User> extends Strategy<User, SteamStrategyVerifyParams> {
    name = "steam";

    constructor(
        private options: SteamStrategyOptions | ((request: Request) => Promise<SteamStrategyOptions>),
        verify: Strategy.VerifyFunction<User, SteamStrategyVerifyParams>
    ) {
        super(verify);
    }

    async authenticate(request: Request): Promise<User> {
        const { apiKey, onError, returnURL, realm } =
            typeof this.options === "function" ? await this.options(request) : this.options;
        const handleError = (error: unknown) => {
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
                if (!result.authenticated || !result.claimedIdentifier) {
                    throw new Error("Not authenticated from result");
                }
                const userId = result.claimedIdentifier.toString().split("/").at(-1);
                if (userId === undefined) {
                    throw new Error("Unable to get SteamID.");
                }
                return await this.verify({
                    user: (await steamApi.getUserSummary(userId)) as UserSummary,
                    request
                });
            } else {
                throw redirect(await authenticateToSteam(relyingParty));
            }
        } catch (error) {
            handleError(error);
            throw error;
        }
    }
}
