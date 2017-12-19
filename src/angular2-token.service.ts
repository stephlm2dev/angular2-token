import { Injectable, Optional } from '@angular/core';
import { ActivatedRoute, Router, CanActivate } from '@angular/router';
import { HttpClient, HttpHeaders, HttpResponse } from '@angular/common/http';

import { Observable } from 'rxjs/Observable';
import 'rxjs/add/operator/share';
import 'rxjs/add/observable/interval';
import 'rxjs/add/observable/fromEvent';
import 'rxjs/add/operator/pluck';
import 'rxjs/add/operator/filter';

import {
    HttpOptions,
    RequestHttpOptions,

    SignInData,
    RegisterData,
    UpdatePasswordData,
    ResetPasswordData,

    UserType,
    UserData,
    AuthData,

    Angular2TokenOptions
} from './angular2-token.model';

@Injectable()
export class Angular2TokenService implements CanActivate {

    get currentUserType(): string {
        if (this.atCurrentUserType != null)
            return this.atCurrentUserType.name;
        else
            return null;
    }

    get currentUserData(): UserData {
        return this.atCurrentUserData;
    }

    get currentAuthData(): AuthData {
        return this.atCurrentAuthData;
    }

    get currentAuthHeaders(): HttpHeaders {
        if (this.atCurrentAuthData != null) {
          return new HttpHeaders({
            'access-token': this.atCurrentAuthData.accessToken,
            'client':       this.atCurrentAuthData.client,
            'expiry':       this.atCurrentAuthData.expiry,
            'token-type':   this.atCurrentAuthData.tokenType,
            'uid':          this.atCurrentAuthData.uid
          });
        }
        return new HttpHeaders;
    }

    private atOptions: Angular2TokenOptions;
    private atCurrentUserType: UserType;
    private atCurrentAuthData: AuthData;
    private atCurrentUserData: UserData;

    constructor(
        private http: HttpClient,
        @Optional() private activatedRoute: ActivatedRoute,
        @Optional() private router: Router
    ) { }

    userSignedIn(): boolean {
        return !!this.atCurrentAuthData;
    }

    canActivate(): boolean {
        if (this.userSignedIn())
            return true;
        else {
            // Store current location in storage (usefull for redirection after signing in)
            if (this.atOptions.signInStoredUrlStorageKey) {
                localStorage.setItem(
                    this.atOptions.signInStoredUrlStorageKey,
                    window.location.pathname + window.location.search
                );
            }

            // Redirect user to sign in if signInRedirect is set
            if(this.router && this.atOptions.signInRedirect)
                this.router.navigate([this.atOptions.signInRedirect]);

            return false;
        }
    }

    // Inital configuration
    init(options?: Angular2TokenOptions) {

        let defaultOptions: Angular2TokenOptions = {
            apiPath:                    null,
            apiBase:                    null,

            signInPath:                 'auth/sign_in',
            signInRedirect:             null,
            signInStoredUrlStorageKey:  null,

            signOutPath:                'auth/sign_out',
            validateTokenPath:          'auth/validate_token',
            signOutFailedValidate:      false,

            registerAccountPath:        'auth',
            deleteAccountPath:          'auth',
            registerAccountCallback:    window.location.href,

            updatePasswordPath:         'auth',

            resetPasswordPath:          'auth/password',
            resetPasswordCallback:      window.location.href,

            userTypes:                  null,

            oAuthBase:                  window.location.origin,
            oAuthPaths: {
                github:                 'auth/github'
            },
            oAuthCallbackPath:          'oauth_callback',
            oAuthWindowType:            'newWindow',
            oAuthWindowOptions:         null,

            globalOptions: {
                headers: {
                    'Content-Type': 'application/json',
                    'Accept':       'application/json'
                }
            }
        };

        this.atOptions = (<any>Object).assign(defaultOptions, options);

        this.tryLoadAuthData();
    }

    /**
     *
     * Actions
     *
     */

    // Register request
    registerAccount(registerData: RegisterData): Observable<UserData> {

        if (registerData.userType == null)
            this.atCurrentUserType = null;
        else {
            this.atCurrentUserType = this.getUserTypeByName(registerData.userType);
            delete registerData.userType;
        }

        registerData.password_confirmation  = registerData.passwordConfirmation;
        delete registerData.passwordConfirmation;

        registerData.confirm_success_url    = this.atOptions.registerAccountCallback;

        return this.post<UserData>(this.getUserPath() + this.atOptions.registerAccountPath, registerData);
    }

    // Delete Account
    deleteAccount(): Observable<UserData> {
        return this.delete<UserData>(this.getUserPath() + this.atOptions.deleteAccountPath);
    }

    // Sign in request and set storage
    signIn(signInData: SignInData): Observable<UserData> {

        if (signInData.userType == null)
            this.atCurrentUserType = null;
        else
            this.atCurrentUserType = this.getUserTypeByName(signInData.userType);

        let body = {
            email:      signInData.email,
            password:   signInData.password
        };

        let observ = this.post<any>(
          this.getUserPath() + this.atOptions.signInPath, body, {observe: 'response'}
        );

        observ.subscribe(res => this.atCurrentUserData = res.body, _error => null);

        return observ;
    }

    signInOAuth(oAuthType: string) {

        let oAuthPath: string = this.getOAuthPath(oAuthType);
        let callbackUrl: string = `${window.location.origin}/${this.atOptions.oAuthCallbackPath}`;
        let oAuthWindowType: string = this.atOptions.oAuthWindowType;
        let authUrl: string = this.getOAuthUrl(oAuthPath, callbackUrl, oAuthWindowType);

        if (oAuthWindowType == 'newWindow') {
            let oAuthWindowOptions = this.atOptions.oAuthWindowOptions;
            let windowOptions = '';

            if (oAuthWindowOptions) {
                for (let key in oAuthWindowOptions) {
                    windowOptions += `,${key}=${oAuthWindowOptions[key]}`;
                }
            }

            let popup = window.open(
                authUrl,
                '_blank',
                `closebuttoncaption=Cancel${windowOptions}`
            );
            return this.requestCredentialsViaPostMessage(popup);
        } else if (oAuthWindowType == 'sameWindow') {
            window.location.href = authUrl;
        } else {
            throw `Unsupported oAuthWindowType "${oAuthWindowType}"`;
        }
    }

    processOAuthCallback(): void {
        this.getAuthDataFromParams();
    }

    // Sign out request and delete storage
    signOut(): Observable<any> {
        let observ = this.delete<any>(this.getUserPath() + this.atOptions.signOutPath);

        localStorage.removeItem('accessToken');
        localStorage.removeItem('client');
        localStorage.removeItem('expiry');
        localStorage.removeItem('tokenType');
        localStorage.removeItem('uid');

        this.atCurrentAuthData = null;
        this.atCurrentUserType = null;
        this.atCurrentUserData = null;

        return observ;
    }

    // Validate token request
    validateToken(): Observable<UserData> {
        let observ = this.get<any>(this.getUserPath() + this.atOptions.validateTokenPath);

        observ.subscribe(
            res => this.atCurrentUserData = res.body,
            error => {
                if (error.status === 401 && this.atOptions.signOutFailedValidate) {
                    this.signOut();
                }
            });

        return observ;
    }

    // Update password request
    updatePassword(updatePasswordData: UpdatePasswordData): Observable<UserData> {

        if (updatePasswordData.userType != null)
            this.atCurrentUserType = this.getUserTypeByName(updatePasswordData.userType);

        let body: any;

        if (updatePasswordData.passwordCurrent == null) {
            body = {
                password:               updatePasswordData.password,
                password_confirmation:  updatePasswordData.passwordConfirmation
            }
        } else {
            body = {
                current_password:       updatePasswordData.passwordCurrent,
                password:               updatePasswordData.password,
                password_confirmation:  updatePasswordData.passwordConfirmation
            };
        }

        if (updatePasswordData.resetPasswordToken) {
            body.reset_password_token = updatePasswordData.resetPasswordToken;
        }

        return this.put<UserData>(this.getUserPath() + this.atOptions.updatePasswordPath, body);
    }

    // Reset password request
    resetPassword(resetPasswordData: ResetPasswordData): Observable<UserData> {

        if (resetPasswordData.userType == null)
            this.atCurrentUserType = null;
        else
            this.atCurrentUserType = this.getUserTypeByName(resetPasswordData.userType);

        let body = {
            email:          resetPasswordData.email,
            redirect_url:   this.atOptions.resetPasswordCallback
        };

        return this.post<UserData>(this.getUserPath() + this.atOptions.resetPasswordPath, body);
    }

    /**
     *
     * HTTP Wrappers
     *
     */

    get<T>(url: string, options: RequestHttpOptions = {}): Observable<T> {
        const httpOptions: Object = this.prepareHttpOptions(options);

        const response = this.http.get<T>(this.getApiPath() + url, httpOptions);
        this.handleResponse(response);

        return response;
    }

    post<T>(url: string, body: any, options: RequestHttpOptions = {}): Observable<T> {
        const httpOptions: Object = this.prepareHttpOptions(options);

        const response = this.http.post<T>(this.getApiPath() + url, body, httpOptions);
        this.handleResponse(response);

        return response;
    }

    put<T>(url: string, body: any, options: RequestHttpOptions = {}): Observable<T> {
        const httpOptions: Object = this.prepareHttpOptions(options);

        const response = this.http.put<T>(this.getApiPath() + url, body, httpOptions);
        this.handleResponse(response);

        return response;
    }

    delete<T>( url: string, options: RequestHttpOptions = {}): Observable<T> {
        const httpOptions: Object = this.prepareHttpOptions(options);

        const response = this.http.delete<T>(this.getApiPath() + url, httpOptions);
        this.handleResponse(response);

        return response;
    }

    patch<T>(url: string, body: any, options: RequestHttpOptions = {}): Observable<T> {
        const httpOptions: Object = this.prepareHttpOptions(options);

        const response = this.http.patch<T>(this.getApiPath() + url, body, httpOptions);
        this.handleResponse(response);

        return response;
    }

    head<T>(path: string, options: RequestHttpOptions = {}): Observable<T> {
        const httpOptions: Object = this.prepareHttpOptions(options);

        const response = this.http.head<T>(this.getApiPath() + path, httpOptions);
        this.handleResponse(response);

        return response;
    }

    options<T>(url: string, options: RequestHttpOptions = {}): Observable<T> {
        const httpOptions: Object = this.prepareHttpOptions(options);

        const response = this.http.options<T>(this.getApiPath() + url, httpOptions);
        this.handleResponse(response);

        return response;
    }

    private prepareHttpOptions(options: RequestHttpOptions): Object {
        let baseHeaders: { [key:string]: string; } = this.atOptions.globalOptions.headers;

        // Get auth data from local storage
        this.getAuthDataFromStorage();

        // Merge auth headers to request if set
        if (this.atCurrentAuthData != null) {
            (<any>Object).assign(baseHeaders, {
                'access-token': this.atCurrentAuthData.accessToken,
                'client':       this.atCurrentAuthData.client,
                'expiry':       this.atCurrentAuthData.expiry,
                'token-type':   this.atCurrentAuthData.tokenType,
                'uid':          this.atCurrentAuthData.uid
            });
        }

        if ('headers' in options)
            baseHeaders = (<any>Object).assign(baseHeaders, options.headers);

        let httpOptions = {
            headers: new HttpHeaders(baseHeaders)
        }

        if ('params' in options)
            httpOptions['params'] = options.params;

        if ('observe' in options)
            httpOptions['observe'] = options.reportProgress;

        if ('reportProgress' in options)
            httpOptions['reportProgress'] = options.reportProgress;

        if ('responseType' in options)
            httpOptions['responseType'] = options.responseType;

        if ('withCredentials' in options)
            httpOptions['withCredentials'] = options.withCredentials;

        return httpOptions;
    }

    // Check if response is complete and newer, then update storage
    private handleResponse(response: Observable<any>): void {
        response.subscribe(res => {
            this.getAuthHeadersFromResponse(<any>res);
        }, error => {
            this.getAuthHeadersFromResponse(<any>error);
        });
    }

    /**
     *
     * Get Auth Data
     *
     */

    // Try to load auth data
    private tryLoadAuthData(): void {

        let userType = this.getUserTypeByName(localStorage.getItem('userType'));

        if (userType)
            this.atCurrentUserType = userType;

        this.getAuthDataFromStorage();

        if(this.activatedRoute)
            this.getAuthDataFromParams();

        if (this.atCurrentAuthData)
            this.validateToken();
    }

    // Parse Auth data from response
    private getAuthHeadersFromResponse(data: any): void {
        let headers = data.headers;

        let authData: AuthData = {
            accessToken:    headers.get('access-token'),
            client:         headers.get('client'),
            expiry:         headers.get('expiry'),
            tokenType:      headers.get('token-type'),
            uid:            headers.get('uid')
        };

        this.setAuthData(authData);
    }

    // Parse Auth data from post message
    private getAuthDataFromPostMessage(data: any): void {
        let authData: AuthData = {
            accessToken:    data['auth_token'],
            client:         data['client_id'],
            expiry:         data['expiry'],
            tokenType:      'Bearer',
            uid:            data['uid']
        };

        this.setAuthData(authData);
    }

    // Try to get auth data from storage.
    private getAuthDataFromStorage(): void {

        let authData: AuthData = {
            accessToken:    localStorage.getItem('accessToken'),
            client:         localStorage.getItem('client'),
            expiry:         localStorage.getItem('expiry'),
            tokenType:      localStorage.getItem('tokenType'),
            uid:            localStorage.getItem('uid')
        };

        if (this.checkAuthData(authData))
            this.atCurrentAuthData = authData;
    }

    // Try to get auth data from url parameters.
    private getAuthDataFromParams(): void {
        if(this.activatedRoute.queryParams) // Fix for Testing, needs to be removed later
            this.activatedRoute.queryParams.subscribe(queryParams => {
                let authData: AuthData = {
                    accessToken:    queryParams['token'] || queryParams['auth_token'],
                    client:         queryParams['client_id'],
                    expiry:         queryParams['expiry'],
                    tokenType:      'Bearer',
                    uid:            queryParams['uid']
                };

                if (this.checkAuthData(authData))
                    this.atCurrentAuthData = authData;
            });
    }

    /**
     *
     * Set Auth Data
     *
     */

    // Write auth data to storage
    private setAuthData(authData: AuthData): void {

        if (this.checkAuthData(authData)) {

            this.atCurrentAuthData = authData;

            localStorage.setItem('accessToken', authData.accessToken);
            localStorage.setItem('client', authData.client);
            localStorage.setItem('expiry', authData.expiry);
            localStorage.setItem('tokenType', authData.tokenType);
            localStorage.setItem('uid', authData.uid);

            if (this.atCurrentUserType != null)
                localStorage.setItem('userType', this.atCurrentUserType.name);

        }
    }

    /**
     *
     * Validate Auth Data
     *
     */

    // Check if auth data complete and if response token is newer
    private checkAuthData(authData: AuthData): boolean {

        if (
            authData.accessToken != null &&
            authData.client != null &&
            authData.expiry != null &&
            authData.tokenType != null &&
            authData.uid != null
        ) {
            if (this.atCurrentAuthData != null)
                return authData.expiry >= this.atCurrentAuthData.expiry;
            else
                return true;
        } else {
            return false;
        }
    }

    /**
     *
     * Construct Paths / Urls
     *
     */

    private getUserPath(): string {
        if (this.atCurrentUserType == null)
            return '';
        else
            return this.atCurrentUserType.path + '/';
    }

    private getApiPath(): string {
        let constructedPath = '';

        if (this.atOptions.apiBase != null)
            constructedPath += this.atOptions.apiBase + '/';

        if (this.atOptions.apiPath != null)
            constructedPath += this.atOptions.apiPath + '/';

        return constructedPath;
    }

    private getOAuthPath(oAuthType: string): string {
        let oAuthPath: string;

        oAuthPath = this.atOptions.oAuthPaths[oAuthType];

        if (oAuthPath == null)
            oAuthPath = `/auth/${oAuthType}`;

        return oAuthPath;
    }

    private getOAuthUrl(oAuthPath: string, callbackUrl: string, windowType: string): string {
        let url: string;

        url =   `${this.atOptions.oAuthBase}/${oAuthPath}`;
        url +=  `?omniauth_window_type=${windowType}`;
        url +=  `&auth_origin_url=${encodeURIComponent(callbackUrl)}`;

        if (this.atCurrentUserType != null)
            url += `&resource_class=${this.atCurrentUserType.name}`;

        return url;
    }

    /**
     *
     * OAuth
     *
     */

    private requestCredentialsViaPostMessage(authWindow: any): Observable<any> {
        let pollerObserv = Observable.interval(500);

        let responseObserv = Observable.fromEvent(window, 'message').pluck('data')
            .filter(this.oAuthWindowResponseFilter);

        let responseSubscription = responseObserv.subscribe(
            this.getAuthDataFromPostMessage.bind(this)
        );

        let pollerSubscription = pollerObserv.subscribe(() => {
            if (authWindow.closed)
                pollerSubscription.unsubscribe();
            else
                authWindow.postMessage('requestCredentials', '*');
        });

        return responseObserv;
    }

    private oAuthWindowResponseFilter(data: any): any {
        if(data.message == 'deliverCredentials' || data.message == 'authFailure')
            return data;
    }

    /**
     *
     * Utilities
     *
     */

    // Match user config by user config name
    private getUserTypeByName(name: string): UserType {
        if (name == null || this.atOptions.userTypes == null)
            return null;

        return this.atOptions.userTypes.find(
            userType => userType.name === name
        );
    }
}
