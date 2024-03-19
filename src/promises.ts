/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Ian Lucas. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import type OpenID from "openid";

export const PromiseAuthenticate = (relyingParty: OpenID.RelyingParty): Promise<string> =>
    new Promise((resolve, reject) => {
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

export const PromiseVerifyAssertion = (
    relyingParty: OpenID.RelyingParty,
    req: Request
): Promise<{
    authenticated: boolean;
    claimedIdentifier?: string | undefined;
}> =>
    new Promise((resolve, reject) => {
        relyingParty.verifyAssertion(req, (err, result) => {
            if (err) {
                return reject(err);
            }
            if (!result) {
                return reject(`No result from verifyAssertion`);
            }
            return resolve(result);
        });
    });
