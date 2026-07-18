import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const sourceUrl = new URL(
	'../assets/js/openai-oauth-connector.js',
	import.meta.url
);
const source = await readFile( sourceUrl, 'utf8' );
const registrations = [];
const component = () => null;
const context = vm.createContext( {
	console,
	window: {
		wp: {
			components: {
				Button: component,
				ExternalLink: component,
				Notice: component,
				RadioControl: component,
				Spinner: component,
				__experimentalHStack: component,
				__experimentalVStack: component,
			},
			element: {
				createElement: component,
				useEffect: component,
				useRef: component,
				useState: component,
			},
			i18n: {
				__: ( text ) => text,
				sprintf: ( format ) => format,
			},
		},
	},
} );
const connectors = new vm.SyntheticModule(
	[
		'__experimentalConnectorItem',
		'__experimentalDefaultConnectorSettings',
		'__experimentalRegisterConnector',
	],
	function setConnectorExports() {
		this.setExport( '__experimentalConnectorItem', component );
		this.setExport( '__experimentalDefaultConnectorSettings', component );
		this.setExport(
			'__experimentalRegisterConnector',
			( slug, config ) => registrations.push( { slug, config } )
		);
	},
	{ context }
);
const subject = new vm.SourceTextModule( source, {
	context,
	identifier: sourceUrl.href,
} );

await subject.link( async ( specifier ) => {
	assert.equal( specifier, '@wordpress/connectors' );
	return connectors;
} );
await subject.evaluate();

assert.equal( registrations.length, 1 );
assert.equal( registrations[ 0 ].slug, 'openai' );
assert.equal( typeof registrations[ 0 ].config.render, 'function' );

console.log( 'PASS connector browser module registers the OpenAI renderer' );
