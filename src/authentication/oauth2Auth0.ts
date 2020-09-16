/*!
* @license
* Copyright 2018 Alfresco Software, Ltd.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

import * as ee from 'event-emitter';
import { AlfrescoApiConfig } from '../alfrescoApiConfig';
import { Authentication } from './authentication';
import * as _minimatch from 'minimatch';
import { AlfrescoApi } from '../alfrescoApi';
import { Observable } from 'rxjs';
import { Oauth2Auth } from './oauth2Auth';
import createAuth0Client, { Auth0Client } from '@auth0/auth0-spa-js';

const EventEmitter: any = ee;

declare let window: Window;

export class Oauth2Auth0 extends Oauth2Auth {

    hashFragmentParams: any;
    token: string;
    discovery: any = {};

    auth0: Auth0Client;

    authentications: Authentication = {
        'oauth2': { accessToken: '' }, type: 'oauth2', 'basicAuth': {}
    };

    iFrameHashListener: any;

    constructor(config: AlfrescoApiConfig, alfrescoApi: AlfrescoApi) {
        super(config, alfrescoApi);

        this.className = 'Oauth2Auth';

        if (config) {
            this.setConfig(config, alfrescoApi);
        }
    }

    setConfig(config: AlfrescoApiConfig, alfrescoApi: AlfrescoApi) {
        this.config = config;

        if (this.config.oauth2) {

            if (this.config.oauth2.host === undefined || this.config.oauth2.host === null) {
                throw 'Missing the required oauth2 host parameter';
            }

            if (this.config.oauth2.clientId === undefined || this.config.oauth2.clientId === null) {
                throw 'Missing the required oauth2 clientId parameter';
            }

            if (this.config.oauth2.scope === undefined || this.config.oauth2.scope === null) {
                throw 'Missing the required oauth2 scope parameter';
            }


            if ((this.config.oauth2.redirectUri === undefined || this.config.oauth2.redirectUri === null) && this.config.oauth2.implicitFlow) {
                throw 'Missing redirectUri required parameter';
            }


            this.basePath = this.config.oauth2.host; //Auth Call

            this.host = this.config.oauth2.host;

            this.discoveryUrls();

            if (this.hasContentProvider()) {
                this.exchangeTicketListener(alfrescoApi);
            }


            this.initOauth(); // jshint ignore:line
        }
    }

    async createAuth0() {

        this.auth0 = await createAuth0Client({
            domain: this.config.oauth2.host,
            client_id: this.config.oauth2.clientId,
            redirect_uri: `${window.location.origin}`,
            audience: this.config.oauth2.audience
        });

    }

    async initOauth() {

        await this.createAuth0();

        const isAuthenticated = await this.auth0.isAuthenticated();


        if (isAuthenticated) {
            const token = await this.auth0.getTokenSilently();
            this.setToken(token, null);
            window.location.href = this.config.oauth2.redirectUri;
        }

        if (!isAuthenticated && this.config.oauth2.implicitFlow) {
            const query = window.location.search;
            const shouldParseResult = query.includes('code=') && query.includes('state=');
            if (shouldParseResult) {
                try {
                    const result = await this.auth0.handleRedirectCallback();

                    if (result.appState && result.appState.targetUrl) {
                        window.location.href = this.config.oauth2.redirectUri;
                    }

                    console.log('Logged in!');
                } catch (err) {
                    console.log('Error parsing redirect:', err);
                }
            } else {
                if (this.config.oauth2.silentLogin && !this.isPublicUrl()) {
                    this.implicitLogin();
                }
            }
        }
    }


    saveUsername(username: string) {
        if (this.storage.supportsStorage()) {
            this.storage.setItem('USERNAME', username);
        }
    }

    implicitLogin() {
        this.redirectLogin();
    }



    getIdToken(): string {
        return this.storage.getItem('id_token');
    }

    getAccessToken(): string {
        return this.storage.getItem('access_token');
    }

    async redirectLogin(redirectPath: string = '/'): Promise<void> {
        if (this.config.oauth2.implicitFlow && typeof window !== 'undefined') {

            this.auth0.loginWithRedirect({
                redirect_uri: `${window.location.origin}`,
                appState: { target: redirectPath }
            });

            //this.emit('implicit_redirect', href);
        }
    }


    /**
     * login Alfresco API
     * @returns {Promise} A promise that returns {new authentication token} if resolved and {error} if rejected.
     * */
    login(username: string, password: string): Promise<any> {
        return new Promise((resolve, reject) => {
            this.grantPasswordLogin(username, password, resolve, reject);
        });
    }

    grantPasswordLogin(username: string, password: string, resolve: any, reject: any) {
        let postBody = {}, pathParams = {}, queryParams = {};

        let headerParams = {
            'Content-Type': 'application/x-www-form-urlencoded'
        };

        let formParams = {
            username: username,
            password: password,
            grant_type: 'password',
            client_id: this.config.oauth2.clientId
        };

        let contentTypes = ['application/x-www-form-urlencoded'];
        let accepts = ['application/json'];

        let promise = this.callCustomApi(
            this.discovery.tokenEndpoint, 'POST',
            pathParams, queryParams, headerParams, formParams, postBody,
            contentTypes, accepts
        ).then(
            (data: any) => {
                this.saveUsername(username);
                this.storeAccessToken(data.access_token, data.expires_in, data.refresh_token);
                this.silentRefresh();
                resolve(data);
            },
            (error) => {
                if (error.error && error.error.status === 401) {
                    this.emit('unauthorized');
                }
                this.emit('error');
                reject(error.error);
            });

        EventEmitter(promise); // jshint ignore:line
    }



    /**
     * Set the current Token
     * */
    setToken(token: string, refreshToken: string) {
        this.authentications.oauth2.accessToken = token;
        this.authentications.oauth2.refreshToken = refreshToken;
        this.authentications.basicAuth.password = null;
        this.token = token;

        this.emit('token_issued');
    }

    /**
     * Get the current Token
     *
     * */
    getToken(): string {
        return this.token;
    }

    /**
     * return the Authentication
     *
     * @returns {Object} authentications
     * */
    getAuthentication(): Authentication {
        return this.authentications;
    }

    /**
     * If the client is logged in return true
     *
     * @returns {Boolean} is logged in
     */
    isLoggedIn(): Observable<boolean> | boolean {
        return !!this.authentications.oauth2.accessToken;
    }

    /**
     * Logout
     **/
    async logOut() {
        this.auth0.logout({
            client_id: this.config.oauth2.clientId,
            returnTo: window.location.origin
        });
    }

}
