/**
 * Replace the default OpenAI connector settings with a choice between an API
 * key and the plugin's experimental account authorization flow.
 *
 * This file intentionally uses wp.element.createElement so it can be loaded as a
 * WordPress script module without a build step.
 */

import {
	__experimentalConnectorItem as ConnectorItem,
	__experimentalDefaultConnectorSettings as DefaultConnectorSettings,
	__experimentalRegisterConnector as registerConnector,
} from '@wordpress/connectors';

const {
	Button,
	ExternalLink,
	Notice,
	RadioControl,
	Spinner,
	__experimentalHStack: HStack,
	__experimentalVStack: VStack,
} = window.wp?.components || {};

const {
	createElement: h,
	useEffect,
	useRef,
	useState,
} = window.wp?.element || {};
const { __, sprintf } = window.wp?.i18n || {};

const TEXT_DOMAIN = 'ai-provider-for-openai';
const REST_BASE = '/ai-provider-for-openai/v1';
const API_KEY_SETTING_FALLBACK = 'connectors_ai_openai_api_key';
const MASKED_API_KEY = '••••••••••••••••';

function getErrorMessage( error, fallback ) {
	return error && typeof error.message === 'string' && error.message
		? error.message
		: fallback;
}

function request( options ) {
	if ( ! window.wp || typeof window.wp.apiFetch !== 'function' ) {
		return Promise.reject(
			new Error(
				__(
					'The WordPress REST API client is not available.',
					TEXT_DOMAIN
				)
			)
		);
	}

	return window.wp.apiFetch( options );
}

function normalizeKeySource( source ) {
	if ( source === 'environment' ) {
		return 'env';
	}
	if (
		source === 'env' ||
		source === 'constant' ||
		source === 'database'
	) {
		return source;
	}
	return 'none';
}

function getCoreFallbackStatus( authentication ) {
	return {
		mode: 'api_key',
		apiKey: {
			configured: Boolean( authentication?.isConnected ),
			source: normalizeKeySource(
				authentication?.source || authentication?.keySource
			),
		},
		oauth: {
			connected: false,
			accountLabel: '',
			errorCode: '',
			errorMessage: '',
		},
		canUseOAuth: false,
	};
}

function normalizeStatus( value, authentication ) {
	const fallback = getCoreFallbackStatus( authentication );
	const apiKey = value && typeof value.apiKey === 'object' ? value.apiKey : {};
	const oauth = value && typeof value.oauth === 'object' ? value.oauth : {};
	const oauthConnected =
		typeof oauth.connected === 'boolean'
			? oauth.connected
			: typeof value?.oauth_connected === 'boolean'
				? value.oauth_connected
				: fallback.oauth.connected;
	const canUseOAuth =
		typeof value?.canUseOAuth === 'boolean'
			? value.canUseOAuth
			: typeof value?.can_use_oauth === 'boolean'
				? value.can_use_oauth
				: typeof value?.encryption_available === 'boolean'
					? value.encryption_available
					: false;

	return {
		mode: value?.mode === 'oauth' ? 'oauth' : 'api_key',
		apiKey: {
			configured:
				typeof apiKey.configured === 'boolean'
					? apiKey.configured
					: typeof value?.has_api_key === 'boolean'
						? value.has_api_key
						: fallback.apiKey.configured,
			source: normalizeKeySource(
				apiKey.source || fallback.apiKey.source
			),
		},
		oauth: {
			connected: oauthConnected,
			accountLabel:
				typeof oauth.accountLabel === 'string'
					? oauth.accountLabel
					: typeof oauth.account_label === 'string'
						? oauth.account_label
						: typeof value?.oauth_account_label === 'string'
							? value.oauth_account_label
							: '',
			errorCode:
				typeof oauth.errorCode === 'string'
					? oauth.errorCode
					: typeof oauth.error_code === 'string'
						? oauth.error_code
						: '',
			errorMessage:
				typeof oauth.errorMessage === 'string'
					? oauth.errorMessage
					: typeof oauth.error_message === 'string'
						? oauth.error_message
						: '',
		},
		canUseOAuth: Boolean( canUseOAuth || oauthConnected ),
	};
}

function getRetryAfter( value ) {
	return (
		value?.retryAfter ??
		value?.retry_after ??
		value?.data?.retryAfter ??
		value?.data?.retry_after
	);
}

function getHttpStatus( error ) {
	const status = Number( error?.data?.status );
	return Number.isFinite( status ) && status >= 400 ? status : null;
}

function normalizeDelay( value, fallback ) {
	const numeric = Number( value );
	const fallbackNumeric = Number( fallback );
	const seconds = Number.isFinite( numeric ) && numeric > 0
		? numeric
		: fallbackNumeric;

	// Keep malformed server values from producing a tight loop or overflowing
	// the browser timer while otherwise honoring the server-provided delay.
	return Math.min( Math.max( seconds || 5, 1 ), 300 ) * 1000;
}

function getVerificationUrl( value ) {
	try {
		const url = new URL( value );
		if ( url.protocol === 'https:' ) {
			return url.href;
		}
	} catch ( error ) {
		// Fall through to the consistent user-facing error below.
	}

	throw new Error(
		__(
			'OpenAI returned an invalid verification URL.',
			TEXT_DOMAIN
		)
	);
}

function getSafeApiKeyDisplay( value ) {
	if ( typeof value !== 'string' || ! value || value === 'invalid_key' ) {
		return '';
	}

	// Current WordPress versions return a masked value. Do not retain a raw key
	// if an older or customized settings endpoint echoes it instead.
	return value.includes( '•' ) ? value : MASKED_API_KEY;
}

function copyTextFallback( value ) {
	const activeElement = document.activeElement;
	const textarea = document.createElement( 'textarea' );
	textarea.value = value;
	textarea.setAttribute( 'readonly', '' );
	textarea.style.position = 'fixed';
	textarea.style.opacity = '0';
	document.body.appendChild( textarea );
	textarea.select();
	let copied = false;
	try {
		copied = document.execCommand( 'copy' );
	} finally {
		textarea.remove();
		if ( activeElement instanceof HTMLElement ) {
			activeElement.focus();
		}
	}

	if ( ! copied ) {
		throw new Error(
			__( 'The code could not be copied.', TEXT_DOMAIN )
		);
	}
}

function ConnectedBadge() {
	return h(
		'span',
		{
			className: 'ai-provider-for-openai-oauth__connected-badge',
			role: 'status',
		},
		__( 'Connected', TEXT_DOMAIN )
	);
}

function OpenAiConnector( props ) {
	const authentication = props.authentication || {};
	const authenticationRef = useRef( authentication );
	authenticationRef.current = authentication;

	const settingName =
		authentication.settingName || API_KEY_SETTING_FALLBACK;
	const helpUrl =
		authentication.credentialsUrl ||
		'https://platform.openai.com/api-keys';
	const name = props.name || props.label || 'OpenAI';
	const description =
		props.description ||
		__(
			'Text and image generation with OpenAI models.',
			TEXT_DOMAIN
		);
	const logo = props.logo || props.icon;

	const [ status, setStatus ] = useState( () =>
		getCoreFallbackStatus( authentication )
	);
	const [ selectedMethod, setSelectedMethod ] = useState( 'api_key' );
	const [ isStatusResolved, setIsStatusResolved ] = useState( false );
	const [ isSettingsResolved, setIsSettingsResolved ] = useState( false );
	const [ statusLoadError, setStatusLoadError ] = useState( '' );
	const [ settingsLoadError, setSettingsLoadError ] = useState( '' );
	const [ currentApiKey, setCurrentApiKey ] = useState( '' );
	const [ isApiKeyRemoving, setIsApiKeyRemoving ] = useState( false );
	const [ isExpanded, setIsExpanded ] = useState( false );
	const [ isModeBusy, setIsModeBusy ] = useState( false );
	const [ oauthBusyAction, setOauthBusyAction ] = useState( '' );
	const [ oauthSession, setOauthSession ] = useState( null );
	const [ pollWarning, setPollWarning ] = useState( '' );
	const [ popupWasBlocked, setPopupWasBlocked ] = useState( false );
	const [ codeWasCopied, setCodeWasCopied ] = useState( false );
	const [ feedback, setFeedback ] = useState( null );
	const oauthSessionRef = useRef( null );

	useEffect( () => {
		let isActive = true;

		request( { path: `${ REST_BASE }/auth/status` } )
			.then( ( value ) => {
				if ( isActive ) {
					const normalized = normalizeStatus(
						value,
						authenticationRef.current
					);
					setStatus( normalized );
					setSelectedMethod( normalized.mode );
					setStatusLoadError( '' );
				}
			} )
			.catch( ( error ) => {
				if ( isActive ) {
					setStatusLoadError(
						getErrorMessage(
							error,
							__(
								'OpenAI account status could not be loaded.',
								TEXT_DOMAIN
							)
						)
					);
				}
			} )
			.finally( () => {
				if ( isActive ) {
					setIsStatusResolved( true );
				}
			} );

		request( { path: '/wp/v2/settings?context=edit' } )
			.then( ( settings ) => {
				if ( ! isActive ) {
					return;
				}
				const savedValue = settings?.[ settingName ];
				setCurrentApiKey( getSafeApiKeyDisplay( savedValue ) );
				setSettingsLoadError( '' );
			} )
			.catch( ( error ) => {
				if ( isActive ) {
					setSettingsLoadError(
						getErrorMessage(
							error,
							__(
								'The saved API key could not be loaded.',
								TEXT_DOMAIN
							)
						)
					);
				}
			} )
			.finally( () => {
				if ( isActive ) {
					setIsSettingsResolved( true );
				}
			} );

		return () => {
			isActive = false;
		};
	}, [ settingName ] );

	// If the connector leaves the page during an unfinished device flow, make
	// a best-effort authenticated request to stop the server-side session.
	useEffect( () => {
		return () => {
			const sessionId = oauthSessionRef.current?.sessionId;
			if ( sessionId ) {
				void request( {
					path: `${ REST_BASE }/oauth/cancel`,
					method: 'POST',
					data: { sessionId },
				} ).catch( () => {} );
			}
		};
	}, [] );

	useEffect( () => {
		if ( ! oauthSession ) {
			return undefined;
		}

		let isStopped = false;
		let timerId;
		const activeSession = oauthSession;

		const finishWithError = ( message ) => {
			if ( isStopped ) {
				return;
			}
			oauthSessionRef.current = null;
			setOauthSession( null );
			setPollWarning( '' );
			setFeedback( { status: 'error', message } );
		};

		const schedulePoll = ( seconds ) => {
			if ( isStopped ) {
				return;
			}
			timerId = window.setTimeout(
				poll,
				normalizeDelay( seconds, activeSession.pollInterval )
			);
		};

		const poll = async () => {
			if ( isStopped ) {
				return;
			}

			if ( Date.now() >= activeSession.expiresAt ) {
				finishWithError(
					__(
						'The OpenAI authorization code expired. Start again to get a new code.',
						TEXT_DOMAIN
					)
				);
				return;
			}

			try {
				const result = await request( {
					path: `${ REST_BASE }/oauth/poll`,
					method: 'POST',
					data: { sessionId: activeSession.sessionId },
				} );

				if ( isStopped ) {
					return;
				}

				if ( result?.status === 'pending' ) {
					setPollWarning( '' );
					schedulePoll(
						getRetryAfter( result ) ?? activeSession.pollInterval
					);
					return;
				}

				if ( result?.status === 'approved' ) {
					let refreshedStatus = null;
					try {
						const value = await request( {
							path: `${ REST_BASE }/auth/status`,
						} );
						refreshedStatus = normalizeStatus(
							value,
							authenticationRef.current
						);
					} catch ( error ) {
						// Approval is authoritative; the status endpoint is only
						// needed to add optional account display information.
					}

					if ( isStopped ) {
						return;
					}

					oauthSessionRef.current = null;
					setOauthSession( null );
					setPollWarning( '' );
					setStatus( ( previous ) => {
						if ( refreshedStatus ) {
							return {
								...refreshedStatus,
								mode: 'oauth',
							};
						}
						return {
							...previous,
							mode: 'oauth',
							oauth: {
								...previous.oauth,
								connected: true,
							},
						};
					} );
					setSelectedMethod( 'oauth' );
					setFeedback( {
						status: 'success',
						message: __(
							'Your OpenAI account is connected.',
							TEXT_DOMAIN
						),
					} );
					return;
				}

				if ( result?.status === 'expired' ) {
					finishWithError(
						result.message ||
							__(
								'The OpenAI authorization code expired. Start again to get a new code.',
								TEXT_DOMAIN
							)
					);
					return;
				}

				finishWithError(
					result?.message ||
						__(
							'OpenAI account authorization could not be completed.',
							TEXT_DOMAIN
						)
				);
			} catch ( error ) {
				if ( isStopped ) {
					return;
				}

				const httpStatus = getHttpStatus( error );
				if ( httpStatus && httpStatus !== 429 ) {
					finishWithError(
						getErrorMessage(
							error,
							__(
								'OpenAI account authorization could not be completed.',
								TEXT_DOMAIN
							)
						)
					);
					return;
				}

				setPollWarning(
					sprintf(
						/* translators: %s: Error returned while checking authorization. */
						__( '%s Retrying automatically.', TEXT_DOMAIN ),
						getErrorMessage(
							error,
							__(
								'WordPress could not check the authorization yet.',
								TEXT_DOMAIN
							)
						)
					)
				);
				schedulePoll(
					getRetryAfter( error ) ?? activeSession.pollInterval
				);
			}
		};

		schedulePoll( activeSession.pollInterval );

		return () => {
			isStopped = true;
			window.clearTimeout( timerId );
		};
	}, [ oauthSession?.sessionId ] );

	const isLoading = ! isStatusResolved || ! isSettingsResolved;
	const isOAuthConnected = status.oauth.connected;
	const isApiKeyConfigured = status.apiKey.configured;
	const isConnected =
		status.mode === 'oauth'
			? isOAuthConnected
			: isApiKeyConfigured;
	const isExternallyConfigured =
		status.apiKey.source === 'env' ||
		status.apiKey.source === 'constant';
	const isBusy = Boolean(
		isModeBusy || isApiKeyRemoving || oauthBusyAction
	);
	const canSelectOAuth = status.canUseOAuth || isOAuthConnected;
	const displayedApiKey =
		currentApiKey ||
		( isApiKeyConfigured || isExternallyConfigured
			? MASKED_API_KEY
			: '' );

	async function cancelOAuthSession() {
		const activeSession = oauthSessionRef.current;
		if ( ! activeSession ) {
			return;
		}

		await request( {
			path: `${ REST_BASE }/oauth/cancel`,
			method: 'POST',
			data: { sessionId: activeSession.sessionId },
		} );
		oauthSessionRef.current = null;
		setOauthSession( null );
		setPollWarning( '' );
		setPopupWasBlocked( false );
		setCodeWasCopied( false );
	}

	async function handleModeChange( nextMode ) {
		if (
			isModeBusy ||
			nextMode === selectedMethod
		) {
			return;
		}

		const previousMethod = selectedMethod;
		setSelectedMethod( nextMode );

		// A new OAuth connection does not become the active authentication
		// method until polling succeeds and the server has stored credentials.
		// Showing the setup panel locally avoids asking the server to activate a
		// method that cannot work yet.
		if ( nextMode === 'oauth' && ! isOAuthConnected ) {
			setFeedback( null );
			return;
		}

		setIsModeBusy( true );
		setFeedback( null );
		try {
			if ( nextMode !== 'oauth' && oauthSessionRef.current ) {
				await cancelOAuthSession();
			}
			await request( {
				path: `${ REST_BASE }/auth/mode`,
				method: 'POST',
				data: { mode: nextMode },
			} );
			setStatus( ( previous ) => ( {
				...previous,
				mode: nextMode,
			} ) );
			setFeedback( {
				status: 'success',
				message: __(
					'OpenAI authentication method updated.',
					TEXT_DOMAIN
				),
			} );
		} catch ( error ) {
			setSelectedMethod( previousMethod );
			setFeedback( {
				status: 'error',
				message: getErrorMessage(
					error,
					__(
						'The authentication method could not be changed.',
						TEXT_DOMAIN
					)
				),
			} );
		} finally {
			setIsModeBusy( false );
		}
	}

	async function saveApiKey( apiKey ) {
		const previousApiKey = currentApiKey;
		const updatedSettings = await request( {
			path: '/wp/v2/settings',
			method: 'POST',
			data: { [ settingName ]: apiKey },
		} );
		const returnedApiKey = updatedSettings?.[ settingName ];

		if (
			! returnedApiKey ||
			returnedApiKey === 'invalid_key' ||
			( previousApiKey && returnedApiKey === previousApiKey )
		) {
			throw new Error(
				__(
					'It was not possible to connect to OpenAI using this key.',
					TEXT_DOMAIN
				)
			);
		}

		setCurrentApiKey( getSafeApiKeyDisplay( returnedApiKey ) );
		setSelectedMethod( 'api_key' );
		setStatus( ( previous ) => ( {
			...previous,
			mode: 'api_key',
			apiKey: {
				configured: true,
				source: 'database',
			},
		} ) );
		setFeedback( {
			status: 'success',
			message: __( 'OpenAI API key saved.', TEXT_DOMAIN ),
		} );
	}

	async function removeApiKey() {
		setIsApiKeyRemoving( true );
		setFeedback( null );
		try {
			await request( {
				path: '/wp/v2/settings',
				method: 'POST',
				data: { [ settingName ]: '' },
			} );
			setCurrentApiKey( '' );
			setStatus( ( previous ) => ( {
				...previous,
				apiKey: {
					configured: false,
					source: 'none',
				},
			} ) );
			setFeedback( {
				status: 'success',
				message: __( 'OpenAI API key removed.', TEXT_DOMAIN ),
			} );
		} catch ( error ) {
			setFeedback( {
				status: 'error',
				message: getErrorMessage(
					error,
					__( 'The API key could not be removed.', TEXT_DOMAIN )
				),
			} );
		} finally {
			setIsApiKeyRemoving( false );
		}
	}

	async function startOAuth() {
		// Open a same-origin blank tab synchronously from the click event. This
		// prevents the browser from treating the later verification navigation
		// (after the REST request) as an unsolicited popup.
		const popup = window.open( '', '_blank' );
		if ( popup ) {
			try {
				popup.opener = null;
				popup.document.title = __(
					'OpenAI authorization',
					TEXT_DOMAIN
				);
				popup.document.body.textContent = __(
					'Preparing OpenAI authorization…',
					TEXT_DOMAIN
				);
			} catch ( error ) {
				// The direct link rendered below remains available as a fallback.
			}
		}

		setOauthBusyAction( 'starting' );
		setFeedback( null );
		setPollWarning( '' );
		setPopupWasBlocked( ! popup );
		setCodeWasCopied( false );

		let sessionId = '';
		try {
			const result = await request( {
				path: `${ REST_BASE }/oauth/start`,
				method: 'POST',
			} );
			sessionId =
				typeof result?.sessionId === 'string'
					? result.sessionId
					: typeof result?.session_id === 'string'
						? result.session_id
						: '';
			const userCode =
				typeof result?.userCode === 'string'
					? result.userCode
					: typeof result?.user_code === 'string'
						? result.user_code
						: '';
			const verificationUrl = getVerificationUrl(
				result?.verificationUrl || result?.verification_url || ''
			);

			if ( ! sessionId || ! userCode ) {
				throw new Error(
					__(
						'OpenAI did not return a complete authorization session.',
						TEXT_DOMAIN
					)
				);
			}

			let parsedExpiresIn = Number(
				result.expiresIn ?? result.expires_in
			);
			if (
				( ! Number.isFinite( parsedExpiresIn ) || parsedExpiresIn <= 0 ) &&
				Number.isFinite( Number( result.expires_at ) )
			) {
				parsedExpiresIn = Number( result.expires_at ) - Date.now() / 1000;
			}
			const parsedPollInterval = Number(
				result.pollInterval ?? result.poll_interval ?? result.interval
			);
			const expiresIn =
				Number.isFinite( parsedExpiresIn ) && parsedExpiresIn > 0
					? parsedExpiresIn
					: 600;
			const pollInterval =
				Number.isFinite( parsedPollInterval ) && parsedPollInterval > 0
					? parsedPollInterval
					: 5;
			const session = {
				sessionId,
				userCode,
				verificationUrl,
				expiresIn,
				expiresAt: Date.now() + expiresIn * 1000,
				pollInterval,
			};
			oauthSessionRef.current = session;
			setOauthSession( session );

			if ( popup && ! popup.closed ) {
				try {
					popup.location.replace( verificationUrl );
				} catch ( error ) {
					setPopupWasBlocked( true );
				}
			} else {
				setPopupWasBlocked( true );
			}
		} catch ( error ) {
			if ( popup && ! popup.closed ) {
				popup.close();
			}
			if ( sessionId ) {
				void request( {
					path: `${ REST_BASE }/oauth/cancel`,
					method: 'POST',
					data: { sessionId },
				} ).catch( () => {} );
			}
			setFeedback( {
				status: 'error',
				message: getErrorMessage(
					error,
					__(
						'OpenAI account authorization could not be started.',
						TEXT_DOMAIN
					)
				),
			} );
		} finally {
			setOauthBusyAction( '' );
		}
	}

	async function handleCancelOAuth() {
		setOauthBusyAction( 'cancelling' );
		setFeedback( null );
		try {
			await cancelOAuthSession();
			setFeedback( {
				status: 'success',
				message: __( 'OpenAI authorization cancelled.', TEXT_DOMAIN ),
			} );
		} catch ( error ) {
			setFeedback( {
				status: 'error',
				message: getErrorMessage(
					error,
					__(
						'The authorization session could not be cancelled.',
						TEXT_DOMAIN
					)
				),
			} );
		} finally {
			setOauthBusyAction( '' );
		}
	}

	async function disconnectOAuth() {
		setOauthBusyAction( 'disconnecting' );
		setFeedback( null );
		try {
			await request( {
				path: `${ REST_BASE }/oauth/connection`,
				method: 'DELETE',
			} );

			let refreshedStatus = null;
			try {
				const value = await request( {
					path: `${ REST_BASE }/auth/status`,
				} );
				refreshedStatus = normalizeStatus(
					value,
					authenticationRef.current
				);
			} catch ( error ) {
				// The successful DELETE is authoritative. The follow-up request
				// only keeps the active-mode display in sync with the server.
			}

			setStatus( ( previous ) =>
				refreshedStatus || {
					...previous,
					mode: 'api_key',
					oauth: {
						connected: false,
						accountLabel: '',
					},
				}
			);
			setSelectedMethod( 'api_key' );
			setFeedback( {
				status: 'success',
				message: __( 'OpenAI account disconnected.', TEXT_DOMAIN ),
			} );
		} catch ( error ) {
			setFeedback( {
				status: 'error',
				message: getErrorMessage(
					error,
					__(
						'The OpenAI account could not be disconnected.',
						TEXT_DOMAIN
					)
				),
			} );
		} finally {
			setOauthBusyAction( '' );
		}
	}

	async function copyUserCode() {
		if ( ! oauthSession?.userCode ) {
			return;
		}

		try {
			if ( navigator.clipboard?.writeText ) {
				await navigator.clipboard.writeText( oauthSession.userCode );
			} else {
				copyTextFallback( oauthSession.userCode );
			}
			setCodeWasCopied( true );
		} catch ( error ) {
			setFeedback( {
				status: 'error',
				message: getErrorMessage(
					error,
					__( 'The code could not be copied.', TEXT_DOMAIN )
				),
			} );
		}
	}

	async function toggleExpanded() {
		if ( isExpanded && oauthSessionRef.current ) {
			setOauthBusyAction( 'cancelling' );
			setFeedback( null );
			try {
				await cancelOAuthSession();
			} catch ( error ) {
				setFeedback( {
					status: 'error',
					message: getErrorMessage(
						error,
						__(
							'The authorization session could not be cancelled.',
							TEXT_DOMAIN
						)
					),
				} );
				setOauthBusyAction( '' );
				return;
			}
			setOauthBusyAction( '' );
		}
		setIsExpanded( ! isExpanded );
	}

	function renderFeedback() {
		if ( ! feedback ) {
			return null;
		}

		return h(
			Notice,
			{
				status: feedback.status,
				isDismissible: true,
				onRemove: () => setFeedback( null ),
			},
			feedback.message
		);
	}

	function renderApiKeySettings() {
		return h(
			'div',
			{ className: 'ai-provider-for-openai-oauth__method-panel' },
			h(
				'p',
				{ className: 'ai-provider-for-openai-oauth__method-description' },
				__(
					'Use an OpenAI Platform API key. Requests use your OpenAI API billing account.',
					TEXT_DOMAIN
				)
			),
			isApiKeyRemoving
				? h(
						HStack,
						{ justify: 'flex-start', spacing: 2 },
						h( Spinner ),
						h(
							'span',
							{ role: 'status' },
							__( 'Removing API key…', TEXT_DOMAIN )
						)
				  )
				: h( DefaultConnectorSettings, {
						key: isApiKeyConfigured
							? 'api-key-connected'
							: 'api-key-setup',
						initialValue: displayedApiKey,
						helpUrl,
						helpLabel: __( 'OpenAI Platform', TEXT_DOMAIN ),
						readOnly:
							isApiKeyConfigured || isExternallyConfigured,
						keySource: status.apiKey.source,
						onSave: saveApiKey,
						onRemove: isExternallyConfigured
							? undefined
							: () => {
									void removeApiKey();
							  },
				  } )
		);
	}

	function renderOAuthSettings() {
		if ( status.oauth.errorMessage ) {
			return h(
				'div',
				{ className: 'ai-provider-for-openai-oauth__method-panel' },
				h(
					Notice,
					{ status: 'warning', isDismissible: false },
					status.oauth.errorMessage
				),
				h(
					Button,
					{
						variant: 'tertiary',
						isDestructive: true,
						disabled: Boolean( oauthBusyAction ),
						accessibleWhenDisabled: true,
						isBusy: oauthBusyAction === 'disconnecting',
						onClick: disconnectOAuth,
					},
					oauthBusyAction === 'disconnecting'
						? __( 'Removing…', TEXT_DOMAIN )
						: __( 'Remove unusable connection', TEXT_DOMAIN )
				)
			);
		}

		if ( ! canSelectOAuth ) {
			return h(
				Notice,
				{ status: 'warning', isDismissible: false },
				__(
					'OpenAI account authorization is not available on this site.',
					TEXT_DOMAIN
				)
			);
		}

		if ( isOAuthConnected ) {
			return h(
				'div',
				{ className: 'ai-provider-for-openai-oauth__method-panel' },
				h(
					Notice,
					{ status: 'success', isDismissible: false },
					status.oauth.accountLabel
						? sprintf(
								/* translators: %s: OpenAI account name or email. */
								__( 'Connected as %s.', TEXT_DOMAIN ),
								status.oauth.accountLabel
						  )
						: __( 'Your OpenAI account is connected.', TEXT_DOMAIN )
				),
				h(
					Button,
					{
						variant: 'tertiary',
						isDestructive: true,
						disabled: Boolean( oauthBusyAction ),
						accessibleWhenDisabled: true,
						isBusy: oauthBusyAction === 'disconnecting',
						onClick: disconnectOAuth,
					},
					oauthBusyAction === 'disconnecting'
						? __( 'Disconnecting…', TEXT_DOMAIN )
						: __( 'Disconnect OpenAI account', TEXT_DOMAIN )
				)
			);
		}

		if ( oauthSession ) {
			const approximateMinutes = Math.max(
				1,
				Math.ceil( oauthSession.expiresIn / 60 )
			);

			return h(
				'div',
				{ className: 'ai-provider-for-openai-oauth__method-panel' },
				popupWasBlocked
					? h(
							Notice,
							{ status: 'warning', isDismissible: false },
							__(
								'The verification tab could not be opened. Use the link below to continue.',
								TEXT_DOMAIN
							)
					  )
					: null,
				h(
					'h3',
					{ className: 'ai-provider-for-openai-oauth__section-title' },
					__( 'Finish connecting', TEXT_DOMAIN )
				),
				h(
					'p',
					null,
					__(
						'Enter this one-time code on the OpenAI verification page:',
						TEXT_DOMAIN
					)
				),
				h(
					'div',
					{ className: 'ai-provider-for-openai-oauth__code-row' },
						h(
						'code',
						{
							className: 'ai-provider-for-openai-oauth__user-code',
						},
						oauthSession.userCode
					),
					h(
						Button,
						{
							variant: 'secondary',
							onClick: copyUserCode,
							'aria-label': codeWasCopied
								? __( 'Verification code copied', TEXT_DOMAIN )
								: __( 'Copy verification code', TEXT_DOMAIN ),
						},
						codeWasCopied
							? __( 'Copied', TEXT_DOMAIN )
							: __( 'Copy code', TEXT_DOMAIN )
					)
				),
				h(
					'p',
					{ className: 'ai-provider-for-openai-oauth__verification-link' },
					h(
						ExternalLink,
						{ href: oauthSession.verificationUrl },
						__( 'Open the OpenAI verification page', TEXT_DOMAIN )
					)
				),
				h(
					'p',
					{ className: 'ai-provider-for-openai-oauth__expires' },
					sprintf(
						/* translators: %d: Approximate number of minutes until the authorization code expires. */
						__( 'This code expires in about %d minutes.', TEXT_DOMAIN ),
						approximateMinutes
					)
				),
				pollWarning
					? h(
							Notice,
							{ status: 'warning', isDismissible: false },
							pollWarning
					  )
					: null,
				h(
					HStack,
					{ justify: 'flex-start', spacing: 3 },
					h( Spinner ),
					h(
						'span',
						{ role: 'status', 'aria-live': 'polite' },
						__( 'Waiting for approval…', TEXT_DOMAIN )
					)
				),
				h(
					Button,
					{
						variant: 'tertiary',
						isDestructive: true,
						disabled: oauthBusyAction === 'cancelling',
						accessibleWhenDisabled: true,
						isBusy: oauthBusyAction === 'cancelling',
						onClick: handleCancelOAuth,
					},
					oauthBusyAction === 'cancelling'
						? __( 'Cancelling…', TEXT_DOMAIN )
						: __( 'Cancel authorization', TEXT_DOMAIN )
				)
			);
		}

		return h(
			'div',
			{ className: 'ai-provider-for-openai-oauth__method-panel' },
				h(
					Notice,
					{ status: 'info', isDismissible: false },
					__(
						'Sign in on OpenAI\'s Codex verification page with a compatible ChatGPT subscription. After approval, the account becomes the active authentication method. This experimental option is separate from OpenAI Platform API billing. OAuth tokens are exchanged and stored server-side and never pass through this browser.',
						TEXT_DOMAIN
					)
			),
			h(
				Button,
				{
					variant: 'primary',
					disabled: Boolean( oauthBusyAction ),
					accessibleWhenDisabled: true,
					isBusy: oauthBusyAction === 'starting',
					onClick: startOAuth,
				},
				oauthBusyAction === 'starting'
					? __( 'Starting…', TEXT_DOMAIN )
					: __( 'Connect OpenAI account', TEXT_DOMAIN )
			)
		);
	}

	const actionArea = h(
		HStack,
		{ spacing: 3, expanded: false },
		isConnected ? h( ConnectedBadge ) : null,
		h(
			Button,
			{
				variant: isExpanded || isConnected ? 'tertiary' : 'secondary',
				size: 'compact',
				disabled: isLoading || isBusy,
				accessibleWhenDisabled: true,
				isBusy: isLoading || isBusy,
				onClick: toggleExpanded,
				'aria-expanded': isExpanded,
			},
			isLoading
				? __( 'Loading…', TEXT_DOMAIN )
				: isExpanded
					? __( 'Close', TEXT_DOMAIN )
					: isConnected
						? __( 'Edit', TEXT_DOMAIN )
						: __( 'Set up', TEXT_DOMAIN )
		)
	);

	return h(
		ConnectorItem,
		{
			className:
				'connector-item--ai-provider-for-openai ai-provider-for-openai-oauth',
			logo,
			name,
			description,
			actionArea,
		},
		isExpanded
			? h(
					VStack,
					{
						spacing: 4,
						className: 'ai-provider-for-openai-oauth__settings',
					},
					statusLoadError
						? h(
								Notice,
								{ status: 'warning', isDismissible: false },
								statusLoadError
						  )
						: null,
					settingsLoadError
						? h(
								Notice,
								{ status: 'warning', isDismissible: false },
								settingsLoadError
						  )
						: null,
					renderFeedback(),
					h( RadioControl, {
						label: __( 'Authentication option', TEXT_DOMAIN ),
						help: __(
							'Choose a credential to configure or use. An unconnected account becomes active only after authorization succeeds. Switching does not delete the other credential.',
							TEXT_DOMAIN
						),
						selected: selectedMethod,
						onChange: handleModeChange,
						disabled: isModeBusy,
						options: [
							{
								label: __( 'API key', TEXT_DOMAIN ),
								value: 'api_key',
							},
							{
								label: __(
									'OpenAI account (experimental)',
									TEXT_DOMAIN
								),
								value: 'oauth',
							},
						],
					} ),
					isStatusResolved &&
						! canSelectOAuth &&
						! statusLoadError &&
						selectedMethod !== 'oauth'
						? h(
								Notice,
								{ status: 'info', isDismissible: false },
								__(
									'OpenAI account authorization is unavailable in the current server configuration.',
									TEXT_DOMAIN
								)
						  )
						: null,
					isModeBusy
						? h(
								HStack,
								{ justify: 'flex-start', spacing: 2 },
								h( Spinner ),
								h(
									'span',
									{ role: 'status' },
									__(
										'Updating authentication method…',
										TEXT_DOMAIN
									)
								)
						  )
						: null,
					selectedMethod === 'oauth'
						? renderOAuthSettings()
						: renderApiKeySettings()
			  )
			: null
	);
}

if ( h && useEffect && useRef && useState ) {
	// WordPress 7's default connector registration upserts server metadata. By
	// registering only a render function for the core `openai` slug, the core
	// name, description, logo, plugin, and authentication metadata are retained.
	registerConnector( 'openai', {
		render: ( props ) => h( OpenAiConnector, props ),
	} );
} else {
	// eslint-disable-next-line no-console
	console.error(
		'AI Provider for OpenAI requires the WordPress React runtime on the Connectors screen.'
	);
}
