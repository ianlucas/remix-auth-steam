/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Ian Lucas. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { redirect, SessionStorage } from "@remix-run/server-runtime";
import { AuthenticateOptions, Strategy, StrategyVerifyCallback } from "remix-auth";
import OpenID from "openid";
import { PromiseAuthenticate, PromiseVerifyAssertion } from "./promises";
import SteamAPI, { UserSummary } from "steamapi";

export interface SteamStrategyOptions {
    returnURL: string;
    realm?: string;
    apiKey: string;
}

export type SteamStrategyVerifyParams = UserSummary;

export class SteamStrategy<User> extends Strategy<User, SteamStrategyVerifyParams> {
    name = "steam";
    private options: SteamStrategyOptions | (() => Promise<SteamStrategyOptions>);

    constructor(
        options: SteamStrategyOptions | (() => Promise<SteamStrategyOptions>),
        verify: StrategyVerifyCallback<User, SteamStrategyVerifyParams>
    ) {
        super(verify);
        this.options = options;
    }

    async authenticate(request: Request, sessionStorage: SessionStorage, options: AuthenticateOptions): Promise<User> {
        const { apiKey, returnURL, realm } = typeof this.options === "function" ? await this.options() : this.options;
        const relyingParty = new OpenID.RelyingParty(returnURL, realm ?? null, true, false, []);
        const steamApi = new SteamAPI(apiKey);
        try {
            const result = await PromiseVerifyAssertion(relyingParty, request);
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
            const result = await PromiseAuthenticate(relyingParty);
            throw redirect(result);
        }
    }
}
