import uuid from 'uuid/v4';

const REQUEST_TYPE = {
	LOGIN: 'LOGIN',
	RENEW_TOKEN: 'RENEW_TOKEN',
	UNKNOWN: 'UNKNOWN'
};

interface AuthConfig {
	tenant?: string;
	clientId: string;
	redirectUri?: string;
	instance?: string;
	endpoints?: string[];
	loginResource?: string;
	callback?: () => void;
	popUp?: boolean;
	state?: string;
	slice?: string;
	cacheLocation?: 'localStorage' | 'sessionStorage';
	extraQueryParameter?: string;
	localLoginUrl?: string;
	postLogoutRedirectUri?: string;
	displayCall?: (url: string) => void;
	anonymousEndpoints?: string[];
	expireOffsetSeconds?: number;
	correlationId?: string;
	loadFrameTimeout?: number;
	navigateToLoginRequestUrl?: boolean;
}

export default class AuthenticationContext {
	CONSTANTS = {
		ACCESS_TOKEN: 'access_token',
		EXPIRES_IN: 'expires_in',
		ID_TOKEN: 'id_token',
		ERROR_DESCRIPTION: 'error_description',
		SESSION_STATE: 'session_state',
		STORAGE: {
			TOKEN_KEYS: 'adal.token.keys',
			ACCESS_TOKEN_KEY: 'adal.access.token.key',
			EXPIRATION_KEY: 'adal.expiration.key',
			STATE_LOGIN: 'adal.state.login',
			STATE_RENEW: 'adal.state.renew',
			NONCE_IDTOKEN: 'adal.nonce.idtoken',
			SESSION_STATE: 'adal.session.state',
			USERNAME: 'adal.username',
			IDTOKEN: 'adal.idtoken',
			ERROR: 'adal.error',
			ERROR_DESCRIPTION: 'adal.error.description',
			LOGIN_REQUEST: 'adal.login.request',
			LOGIN_ERROR: 'adal.login.error',
			RENEW_STATUS: 'adal.token.renew.status'
		},
		RESOURCE_DELIMETER: '|',
		LOADFRAME_TIMEOUT: 6000,
		TOKEN_RENEW_STATUS_CANCELED: 'Canceled',
		TOKEN_RENEW_STATUS_COMPLETED: 'Completed',
		TOKEN_RENEW_STATUS_IN_PROGRESS: 'In Progress',
		LOGGING_LEVEL: {
			ERROR: 0,
			WARN: 1,
			INFO: 2,
			VERBOSE: 3
		},
		LEVEL_STRING_MAP: {
			0: 'ERROR:',
			1: 'WARNING:',
			2: 'INFO:',
			3: 'VERBOSE:'
		},
		POPUP_WIDTH: 483,
		POPUP_HEIGHT: 600
	};

	_singletonInstance = this;

	instance = 'https://login.microsoftonline.com/';

	config: AuthConfig;
	callback = null;
	popUp = false;
	_idTokenNonce: string;

	private _user = null;
	private _activeRenewals = {};
	private _loginInProgress = false;
	private _acquireTokenInProgress = false;

	constructor(config: AuthConfig) {
		(window as any).renewSates = [];
		(window as any).callBackMappedToRenewState = {};
		(window as any).callBacksMappedToRenewStates = {};

		this.config = {
			...config,
			navigateToLoginRequestUrl: config.navigateToLoginRequestUrl ? config.navigateToLoginRequestUrl : true,
			loginResource: config.loginResource ? config.loginResource : config.clientId,
			redirectUri: config.redirectUri ? config.redirectUri : window.location.href.split('?')[0].split('#')[0],
			postLogoutRedirectUri: config.postLogoutRedirectUri
				? config.postLogoutRedirectUri
				: window.location.href.split('?')[0].split('#')[0],
			anonymousEndpoints: config.anonymousEndpoints ? config.anonymousEndpoints : []
		};

		if (config.callback) {
			this.callback = config.callback;
		}

		if (config.instance) {
			this.instance = config.instance;
		}

		if (config.popUp) {
			this.popUp = config.popUp;
		}

		if (config.loadFrameTimeout) {
			this.CONSTANTS.LOADFRAME_TIMEOUT = config.loadFrameTimeout;
		}
	}

	login(loginStartPage?: string) {
		if (this._loginInProgress) {
			return;
		}

		const expectedState = uuid();
		this.config.state = expectedState;
		this._idTokenNonce = uuid();

		this._saveItem(this.CONSTANTS.STORAGE.LOGIN_REQUEST, loginStartPage || window.location.href);
		this._saveItem(this.CONSTANTS.STORAGE.LOGIN_ERROR, '');
		this._saveItem(this.CONSTANTS.STORAGE.STATE_LOGIN, expectedState);
		this._saveItem(this.CONSTANTS.STORAGE.NONCE_IDTOKEN, this._idTokenNonce);
		this._saveItem(this.CONSTANTS.STORAGE.ERROR, '');
		this._saveItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, '');

		const urlNavigate = `${this._getNavigateUrl('id_token', null)}&nonce=${encodeURIComponent(this._idTokenNonce)}`;
		this._loginInProgress = true;
		if (this.config.displayCall) {
			console.log(this.config);
			this.config.displayCall(urlNavigate);
		} else {
			console.log('prompt', this.config);
			this.promptUser(urlNavigate);
		}

		/* punting on this
		else if (this.popUp) {
			this._loginPopup(urlNavigate)
		}
		*/
	}

	promptUser(urlNavigate?: string) {
		if (urlNavigate) {
			window.location.replace(urlNavigate);
		}
	}

	registerCallback(
		expectedState: string,
		resource: string,
		callback: (errorDesc: string, token: string, error: string) => void
	) {
		this._activeRenewals[resource] = expectedState;
		if (!(window as any).callBacksMappedToRenewStates[expectedState]) {
			(window as any).callBacksMappedToRenewStates[expectedState] = [];
		}
		(window as any).callBackMappedToRenewStates[expectedState].push(callback);
		if (!(window as any).callBackMappedToRenewStates[expectedState]) {
			(window as any).callBackMappedToRenewStates[expectedState] = (errorDesc, token, error) => {
				this._activeRenewals[resource] = null;

				for (let i = 0; i < (window as any).callBacksMappedToRenewStates[expectedState].length; ++i) {
					try {
						(window as any).callBacksMappedToRenewStates[expectedState][i](errorDesc, token, error);
					} catch (error) {}
				}
				(window as any).callBacksMappedToRenewStates[expectedState] = null;
				(window as any).callBackMappedToRenewStates[expectedState] = null;
			};
		}
	}

	private _getItem(key) {}

	private _saveItem(itemKey: string, value: string) {
		if (this.config && this.config.cacheLocation && this.config.cacheLocation === 'localStorage') {
			if (!window.localStorage) {
				return false;
			}

			localStorage.setItem(itemKey, value);

			return true;
		}

		// Default as session storage
		if (!window.sessionStorage) {
			return false;
		}

		sessionStorage.setItem(itemKey, value);
		return true;
	}
	private _getNavigateUrl(responseType: string, resource: string | null): string {
		const tenant = this.config.tenant ? this.config.tenant : 'common';

		const urlNavigate = `${this.instance}${tenant}/oauth2/authorize${this._serialize(
			responseType,
			this.config,
			resource
		)}${this._addLibMetadata()}`;

		return urlNavigate;
	}

	private _renewToken(resource, callback) {
		const frameHandle = this._addAdalFrame('adalRenewFrame' + resource);
		const expectedState = `${uuid()}|${resource}`;
		this.config.state = expectedState;
		(window as any).renewStates.push(expectedState);
		const urlNavigate = this._addHintParameters(`${this._getNavigateUrl('token_id', resource)}&prompt=none`);
		this.registerCallback(expectedState, resource, callback);
		frameHandle.src = 'about:blank';
		this._loadFrameTimeout(urlNavigate, 'adalRenewFrame' + resource, resource);
	}

	private _loadFrameTimeout(urlNavigate, frameName, resource) {
		this._saveItem(this.CONSTANTS.STORAGE.RENEW_STATUS + resource, this.CONSTANTS.TOKEN_RENEW_STATUS_IN_PROGRESS);
		this._loadFrame(urlNavigate, frameName);

		setTimeout(() => {
			if (
				this._getItem(
					this.CONSTANTS.STORAGE.RENEW_STATUS + resource,
					this.CONSTANTS.TOKEN_RENEW_STATUS_IN_PROGRESS
				)
			) {
				const expectedState = this._activeRenewals[resource];
				if (expectedState && (window as any).callBackMappedToRenewStates[expectedState]) {
					(window as any).callBackMappedToRenewStates[expectedState](
						'Token renewal operation failed due to timeout',
						null,
						'Token Renewal Failed'
					);
				}
				this._saveItem(
					this.CONSTANTS.STORAGE.RENEW_STATUS + resource,
					this.CONSTANTS.TOKEN_RENEW_STATUS_CANCELED
				);
			}
		}, this.CONSTANTS.LOADFRAME_TIMEOUT);
	}

	private _loadFrame(urlNavigate, frameName) {
		// This trick overcomes iframe navigation in IE
		// IE does not load the page consistently in iframe

		const frameCheck = frameName;
		setTimeout(() => {
			const frameHandle = this._addAdalFrame(frameCheck);
			if (frameHandle.src === '' || frameHandle.src === 'about:blank') {
				frameHandle.src = urlNavigate;
				this._loadFrame(urlNavigate, frameCheck);
			}
		}, 500);
	}

	private _serialize(responseType, obj: AuthConfig, resource): string {
		const str = [];
		if (obj !== null) {
			str.push(`?response_type=${responseType}`);
			str.push(`client_id=${encodeURIComponent(obj.clientId)}`);

			if (resource) {
				str.push('resource=' + encodeURIComponent(resource));
			}

			str.push('redirect_uri=' + encodeURIComponent(obj.redirectUri));
			str.push('state=' + encodeURIComponent(obj.state));

			if (obj.hasOwnProperty('slice')) {
				str.push('slice=' + encodeURIComponent(obj.slice));
			}

			if (obj.hasOwnProperty('extraQueryParameter')) {
				str.push(obj.extraQueryParameter);
			}

			const correlationId = obj.correlationId ? obj.correlationId : uuid();
			str.push('client-request-id=' + encodeURIComponent(correlationId));
		}

		console.log(str.join('&'));

		return str.join('&');
	}

	private _addHintParameters(urlNavigate: string) {
		// include hint params only if upn is present
		if (this._user && this._user.profile && this._user.profile.hasOwnProperty('upn')) {
			// don't add login_hint twice if user provided it in the extraQueryParameter value
			if (!this._urlContainsQueryStringParameter('login_hint', urlNavigate)) {
				// add login_hint
				urlNavigate += '&login_hint=' + encodeURIComponent(this._user.profile.upn);
			}

			// don't add domain_hint twice if user provided it in the extraQueryParameter value
			if (
				!this._urlContainsQueryStringParameter('domain_hint', urlNavigate) &&
				this._user.profile.upn.indexOf('@') > -1
			) {
				const parts = this._user.profile.upn.split('@');
				// local part can include @ in quotes. Sending last part handles that.
				urlNavigate += '&domain_hint=' + encodeURIComponent(parts[parts.length - 1]);
			}
		}

		return urlNavigate;
	}

	private _addAdalFrame(iframeId: string): HTMLIFrameElement {
		if (typeof iframeId === 'undefined') {
			return;
		}

		let adalFrame = document.getElementById(iframeId) as HTMLIFrameElement;

		if (!adalFrame) {
			if (
				document.createElement &&
				document.documentElement &&
				((window as any).opera || window.navigator.userAgent.indexOf('MSIE 5.0') === -1)
			) {
				const ifr = document.createElement('iframe');
				ifr.setAttribute('id', iframeId);
				ifr.setAttribute('aria-hidden', 'true');
				ifr.style.visibility = 'hidden';
				ifr.style.position = 'absolute';
				ifr.style.width = ifr.style.height = ifr.style.borderWidth = '0px';

				adalFrame = document.getElementsByTagName('body')[0].appendChild(ifr);
			} else if (document.body && document.body.insertAdjacentHTML) {
				document.body.insertAdjacentHTML(
					'beforeend',
					'<iframe name="' + iframeId + '" id="' + iframeId + '" style="display:none"></iframe>'
				);
			}
			if (window.frames && window.frames[iframeId]) {
				adalFrame = window.frames[iframeId];
			}
		}

		return adalFrame;
	}

	private _urlContainsQueryStringParameter(name, url) {
		// regex to detect pattern of a ? or & followed by the name parameter and an equals character
		const regex = new RegExp('[\\?&]' + name + '=');
		return regex.test(url);
	}

	private _addLibMetadata() {
		return '&x-client-SKU=Js&x-client-Ver=' + this._libVersion();
	}

	private _libVersion() {
		return '0.0.1';
	}
}
