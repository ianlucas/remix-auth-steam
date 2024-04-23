/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Ian Lucas. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { redirect, SessionStorage } from "@remix-run/server-runtime";
import OpenID from "openid";
import { AuthenticateOptions, Strategy, StrategyVerifyCallback } from "remix-auth";
import SteamAPI, { UserSummary } from "steamapi";

export interface SteamStrategyOptions {
    returnURL: string;
    realm?: string;
    apiKey: string;
}

export type SteamStrategyVerifyParams = UserSummary;

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
    private options: SteamStrategyOptions | ((request: Request) => Promise<SteamStrategyOptions>);

    constructor(
        options: SteamStrategyOptions | (() => Promise<SteamStrategyOptions>),
        verify: StrategyVerifyCallback<User, SteamStrategyVerifyParams>
    ) {
        super(verify);
        this.options = options;
    }

    async authenticate(request: Request, sessionStorage: SessionStorage, options: AuthenticateOptions): Promise<User> {
        const { apiKey, returnURL, realm } =
            typeof this.options === "function" ? await this.options(request) : this.options;
        const relyingParty = new OpenID.RelyingParty(returnURL, realm ?? null, true, false, []);
        const steamApi = new SteamAPI(apiKey);
        try {
            const result = await verifySteamAssertion(relyingParty, request);
            if (!result.authenticated || !result.claimedIdentifier)
                return this.failure(`Not authenticated from result`, request, sessionStorage, options);
            try {
                const userSteamID = result.claimedIdentifier.toString().split("/").at(-1)!;
                const steamUserSummary = (await steamApi.getUserSummary(userSteamID)) as UserSummary;
                const user = await this.verify(steamUserSummary);
                return this.success(user, request, sessionStorage, options);
            } catch (error) {
                let message = (error as Error).message;
                return this.failure(message, request, sessionStorage, options);
            }
        } catch {
            throw redirect(await authenticateToSteam(relyingParty));
        }
    }
}
