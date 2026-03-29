<?php
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Context\RequestContext;

class Fail2LogClass {

	public static function onAuthManagerLoginAuthenticateAudit(
		AuthenticationResponse $response,
		$user,
		$username,
		$extraData = []
	) {
		global $wgFail2LogFile, $wgFail2LogUseUTC;
		$useUTC = $wgFail2LogUseUTC ?? true;

		// Return on authentication success
		if ( $response->status !== AuthenticationResponse::FAIL ) {
			return;
		}

		// Use MediaWiki getIP to obtain client IP. It handles proxies
		// and uses X-Forwarded-For only from trusted sources.
		$request = RequestContext::getMain()->getRequest();
		$ip = $request->getIP() ?? 'unknown';
		

		// Ensure $username is a non-empty string for logging
		if ( $username === null || trim( $username ) === '' ) {
			$logUsername = '<unknown>';
		} else {
			$logUsername = (string)$username;
		}

		// Replace Unicode control chars
		$tmp = preg_replace( '/\p{C}/u', '?', $logUsername );

		// preg_replace returns null on malformed Unicode encodings
		if ( $tmp !== null ) {
			$logUsername = $tmp;
		} else {
			// Keep only printable ASCII characters
			$logUsername = preg_replace( '/[^\x20-\x7E]/', '?', $logUsername );
		}

		// Use UTC by default; otherwise log local time
		if ( $useUTC ) {
			$time = gmdate( 'Y-m-d H:i:s O' );
		} else {
			$time = date( 'Y-m-d H:i:s O' );
		}

		$line = "Failed:$ip $time $logUsername\n";

		if ( error_log( $line, 3, $wgFail2LogFile ) === false ) {
		 	// Log an error if writing to $wgFail2LogFile fails
			error_log(
				"Fail2Log write failed for $wgFail2LogFile: " .
				rtrim( $line, "\n" )
			);
		}
	}
}
