/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Ian Lucas. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { redirect } from "react-router";
import { Strategy } from "remix-auth/strategy";
import { SteamOpenID } from "./openid.js";

namespace SteamStrategy {
    export interface Options {
        returnURL: string;
    }

    export type VerifyOptions = {
        request: Request;
        userID: string;
    };
}

export class SteamStrategy<User> extends Strategy<User, SteamStrategy.VerifyOptions> {
    name = "steam";

    constructor(
        private options: SteamStrategy.Options | ((request: Request) => Promise<SteamStrategy.Options>),
        verify: Strategy.VerifyFunction<User, SteamStrategy.VerifyOptions>
    ) {
        super(verify);
    }

    async authenticate(request: Request): Promise<User> {
        const { returnURL } = typeof this.options === "function" ? await this.options(request) : this.options;
        const steamOpenID = new SteamOpenID(returnURL, request);
        if (steamOpenID.shouldValidate()) {
            const userID = await steamOpenID.validate();
            return await this.verify({
                userID,
                request
            });
        } else {
            throw redirect(steamOpenID.getAuthUrl());
        }
    }
}
