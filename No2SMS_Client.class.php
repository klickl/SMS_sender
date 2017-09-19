<?php
/*
 * This file implement a PHP class for Net Oxygen's SMS gateway.
 *
 * Its goal is to provide a simple, coherent, complete and documented interface
 * allowing its use in both simple scripts and large applications.
 *
 * At the time (and for all the 1.x branche), XML-RPC is the only protocol
 * supported. The implementation make use of IXR (The Incutio XML-RPC Library).
 * You should have been distributed a copy with this file but can also download
 * it at http://scripts.incutio.com/xmlrpc/ (testing was done using IXR 1.7.4).
 *
 * @version
 *   1.5.0 (16.05.2014)
 *
 * @author
 *   Alexandre Perrin <alexandre.perrin@netoxygen.ch>
 *
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2013-2014 Net Oxygen <info@netoxygen.ch>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/**
 * Net Oxygen's SMS API Client class.
 *
 * This class implement a complete interface to Net Oxygen's SMS gateway via
 * XML-RPC.
 *
 * @see https://sms.netoxygen.ch/api2/documentation/
 *
 * Classic usage would create a new instance providing a user and password used
 * for API credential, and then start to call API methods (beginning by auth(),
 * in order to test credentials, is a good start). Note that an instance is
 * bound to the user and password provided at construction. If you need to
 * change them just create a new instance.
 *
 * The method are declared in the most-used-order to ease reading the code and
 * comments.
 *
 * Example:
 *
 *  $client = new No2SMS_Client($user, $password);
 *  if (!$client->auth())
 *      die('wrong user or password');
 *  $response = $client->send_message($destination, $message);
 *
 * Advanced usage can use subclass No2SMS_Client. Both _success() and _error()
 * were designed to be overrided allowing tight integration and reducing the
 * need to write a complete wrapper around this class.
 *
 * Example: a simple subclass that log activity to stdout
 *
 *   class MySMS_Client extends No2SMS_Client {
 *       protected function _success($method, $argv, $data) {
 *           printf("[%s] INFO: Successfull call to %s\n", date(DATE_RFC822), $method);
 *           return parent::_success($method, $argv, $data);
 *       }
 *
 *       protected function _error($method, $argv, $message, $code) {
 *           printf("[%s] ERROR: call to %s returned %s\n", date(DATE_RFC822), $method, $message);
 *           return parent::_error($method, $argv, $message, $code);
 *       }
 *  }
 */
class No2SMS_Client {
    const XMLRPC_API_URI = 'https://sms.netoxygen.ch/api2/';

    /**
     * API credentials.
     */
    protected $user;
    protected $password;

    /**
     * true if debug output is wanted, false otherwise.
     */
    protected $debug;

    /**
     * Protocol client.
     */
    protected $handler;

    /**
     * Create a new Client.
     *
     * This constructor require a user and password couple used as credential
     * for the API.
     *
     * @param $user (required)
     *   The user user for authentication (string)
     *
     * @param $password (required)
     *   The password user for authentication (string)
     *
     * @param $protocol (optional, default: 'XML-RPC')
     *   The protocol that should be used. Currently only `XML-RPC' is
     *   supported.
     */
    public function __construct($user, $password, $protocol='XML-RPC') {
        if ($protocol === 'XML-RPC') {
            /*
             * conditionnaly require the IXR library, so we can be required in an env that
             * already have IXR loaded.
             */
            if (!class_exists('IXR_Client'))
                require_once('IXR_Library.php');
            $this->handler = new IXR_Client(No2SMS_Client::XMLRPC_API_URI);
        } else
            throw new Exception("$protocol: protocol not supported.");

        $this->user     = (string) $user;
        $this->password = (string) $password;
        $this->disable_debug();
    }

    /**
     * Test if this client has debug enabled.
     *
     * @return
     *   True if debug is enabled, false otherwise.
     */
    public function has_debug_enabled() {
        return $this->debug;
    }

    /**
     * Set this client in debug mode.
     */
    public function enable_debug() {
        $this->debug = $this->handler->debug = TRUE;
    }

    /**
     * Disable debug mode for this client.
     */
    public function disable_debug() {
        $this->debug = $this->handler->debug = FALSE;
    }

    /**
     * Test credentials.
     *
     * This method can be used to test the API credential (user and password).
     * It will try to authenticate and return the result.
     *
     * @return
     *   True when the authentication was a success, false otherwise.
     *
     * If a connection or protocol error arise, an Exception is thrown.
     */
    public function auth() {
        return $this->_RPC('auth', $this->user, $this->password);
    }

    /**
     * This method is used to send a SMS to one or more destination(s).
     *
     * All parameters are expected to be encoded in either UTF-8, ASCII
     * (compatible with UTF-8) or ISO-8859-15 (will be converted into UTF-8).
     *
     * @param $to (required)
     *   The destination number(s). If you want to send the message to only one
     *   destination you can pass directly a string, otherwise use an array of
     *   string to define multiple destination numbers.
     *
     * @param $message (required)
     *   The message to send (string).
     *
     * @param $from (optional, default: '')
     *   This string is displayed as the 'sender' when a SMS a recieved. If
     *   $from is empty or the user is not able to force the 'sender' field,
     *   the default (configured through the account) is used. If no default is
     *   configured then "textobox.ch" is used.
     *
     * @param $date (optional, default: '')
     *   When the message should be sent (based on the Europe/Zurich timezone).
     *   If this parameter is either empty, in the past or invalid the message
     *   is sent immediately. The default is to send immediately. The expected
     *   format is the following:
     *   "2013-04-12 02:45:02"
     *
     * @param $type (optional, default: 'text')
     *   Either "text" or "flash". "flash" SMS are usually displayed without
     *   needing to be opened but are not saved.
     *
     * @return
     *   An array of responses, containing one element for each SMS requested.
     *   The returned array elements are array with the following keys:
     *
     *   0: the destination number
     *   1: the status code for this SMS
     *   2: a unique SMS-ID that can be used. see get_status().
     *
     * If a connection or protocol error arise, an Exception is thrown.
     */
    public function send_message($to, $message, $from='', $date='', $type='text') {
        $to      = (is_array($to) ? $to : array($to));
        $message = (No2SMS_Client::is_utf8($message) ? $message : utf8_encode($message));
        $from    = (No2SMS_Client::is_utf8($from)    ? $from    : utf8_encode($from));
        $date    = (No2SMS_Client::is_utf8($date)    ? $date    : utf8_encode($date));

        return $this->_RPC('send_message',
            $this->user, $this->password, $to, $message, $from, $date, $type
        );
    }

    /**
     * Cancel a SMS.
     *
     * @param $id (required)
     *   A SMS-ID (string), see send_message(). You can get the
     *   status of several SMS by passing an array of SMS-ID.
     *
     * @return
     *   An array of responses, containing one element for each SMS-ID
     *   requested. The returned array elements are array with the following
     *   keys:
     *
     *   0: the provided SMS-ID
     *   1: TRUE if the cancel was a success, FALSE otherwise.
     *
     * If a connection or protocol error arise, an Exception is thrown.
     */
    public function cancel_message($id) {
        $id = (is_array($id) ? $id : array($id));

        return $this->_RPC('cancel_message', $this->user, $this->password, $id);
    }

    /**
     * Get a SMS's status.
     *
     * This method can be used to test a SMS status (if it has been
     * successfully sent, still in the SMS queue, etc.).
     *
     * @param $id (required)
     *   A SMS-ID (string), see send_message(). You can get the
     *   status of several SMS by passing an array of SMS-ID.
     *
     * @return
     *   An array of responses, containing one element for each SMS-ID given as
     *   parameter. The returned array elements are array with the following
     *   keys:
     *   0: the SMS-ID
     *   1: associative array as following:
     *     - from: the 'from' string given. see send_message().
     *     - to: the destination number of this SMS. see send_message().
     *     - length: the message's length.
     *     - sent_date: The date at the time of sending. see send_message().
     *     - sent_status: The status at the time of sending. see send_message().
     *     - sent_status_text: A descriptive text of the sent_status field (in
     *         english).
     *     - last_date: The date of the last notification.
     *     - last_status: The status of at the last notification time.
     *     - last_status_text: A descriptive text of the last_status field (in
     *         english).
     *
     * If a connection or protocol error arise, an Exception is thrown.
     */
    public function get_status($id) {
        $id = (is_array($id) ? $id : array($id));

        return $this->_RPC('get_status', $this->user, $this->password, $id);
    }

    /**
     * Get the total credit for the account.
     *
     * @return
     *   An integer value. Note that if your account type allow to go bellow
     *   zero credits count, the returned value can be negative.
     *   If a connection or protocol error arise, an Exception is thrown.
     *
     * If a connection or protocol error arise, an Exception is thrown.
     */
    public function get_credits() {
        return $this->_RPC('get_credits', $this->user, $this->password);
    }

    /**
     * Get your account type.
     *
     * @return
     *   A description string of your account type like 'free' or 'regular'.
     *   If a connection or protocol error arise, an Exception is thrown.
     *
     * If a connection or protocol error arise, an Exception is thrown.
     */
    public function account_status() {
        return $this->_RPC('account_status', $this->user, $this->password);
    }

    /**
     * Get your account's group id.
     *
     * This method is designed for complex application, allowing them to have
     * different settings at the group level and not only at the user level.
     *
     * @return
     *   API guid are represented as strings of 36 characters in the following
     *   form: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
     *   where x is an hexadecimal digit ([0-9][a-f]).
     *
     * If a connection or protocol error arise, an Exception is thrown.
     */
    public function get_guid() {
        return $this->_RPC('get_guid', $this->user, $this->password);
    }

    /**
     * Internal success handler.
     *
     * This method can be used to customize API responses. Every successfull
     * RPC will pass through this method before returning to the
     * caller.
     *
     * This method is not supposed to be called by user code but overrided in
     * subclasses. This default implementation just return the response as-is.
     *
     * @param $method
     *   The RPC methodName called.
     *
     * @param $argv
     *   The RPC parameters.
     *
     * @param $data
     *   The RPC response from the server.
     */
    protected function _success($method, $argv, $data) {
        return $data;
    }

    /**
     * Internal error handler.
     *
     * This method can be used to customize API responses. Every unsuccessfull
     * RPC will pass through this method before returning to the
     * caller.
     *
     * This method is not supposed to be called by user code but overrided in
     * subclasses to customize error handling. This default implementation
     * throw an exception using the error code and message provided.
     *
     * @param $method
     *   The RPC method called.
     *
     * @param $argv
     *   The RPC parameters.
     *
     * @param $message
     *   The error message.
     *
     * @param $code
     *   The error code.
     */
    protected function _error($method, $argv, $message, $code) {
        throw new No2SMS_Exception($message, $code);
    }

    /**
     * private method to send RPC request and handle errors.
     *
     * @param
     *   This function accept multiple arguments that are forwarded the the
     *   RPC handler.
     *
     * @return
     *   The RPC call's answer. If a connection or protocol error arise,
     *   No2SMS_Client->_error() is called and it will throw an exception.
     */
    protected function _RPC(/* ... */) {
        /*
         * call_user_func_array() and func_get_args() are slow, however the
         * synchronous RPC call will make the performance hit
         * insignificant.
         */
        $argv = func_get_args();
        $success = call_user_func_array(
            array($this->handler, 'query'),
            $argv
        );

        $method = array_shift($argv);
        if ($success) {
            return $this->_success(
                $method,
                $argv,
                $this->handler->getResponse()
            );
        } else {
            return $this->_error(
                $method,
                $argv,
                $this->handler->getErrorMessage(),
                $this->handler->getErrorCode()
            );
        }
        /* NOTREACHED */
    }

    /**
     * Test if a string is encoded in UTF-8.
     *
     * @see http://www.php.net/manual/fr/function.mb-detect-encoding.php#50087
     *
     * @param $string (required)
     *   The string to test.
     *
     * @return
     *   true if $string is valid UTF-8 and false otherwise.
     */
    public static function is_utf8($string) {
        // From http://w3.org/International/questions/qa-forms-utf-8.html
        return preg_match('%^(?:
              [\x09\x0A\x0D\x20-\x7E]            # ASCII
            | [\xC2-\xDF][\x80-\xBF]             # non-overlong 2-byte
            |  \xE0[\xA0-\xBF][\x80-\xBF]        # excluding overlongs
            | [\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}  # straight 3-byte
            |  \xED[\x80-\x9F][\x80-\xBF]        # excluding surrogates
            |  \xF0[\x90-\xBF][\x80-\xBF]{2}     # planes 1-3
            | [\xF1-\xF3][\x80-\xBF]{3}          # planes 4-15
            |  \xF4[\x80-\x8F][\x80-\xBF]{2}     # plane 16
        )*$%xs', $string);
    }

    /**
     * Get some useful information about a message.
     *
     * This method will return informations about a given message like
     * character count, number of SMS needed etc. (see the return section for
     * the exhaustive list).
     *
     * @param $message (required)
     *   The message to analyze (string). As for send_message(), it is expected
     *   to be encoded in either ASCII, ISO-8859-1 or UTF-8.
     *
     * @param $extra (optional, default: false)
     *   If true, exta data (informations in bytes) are provided.
     *
     * @return
     *   An associative array with the following keys defined:
     *   - message_utf8: The message argument converted in UTF-8.
     *   - encoding: 'GSM-7bit' or 'UCS-2'.
     *   - SMS: number of SMS needed for the message (int).
     *   - characters: number of used characters in the message (int).
     *   - remaining: number of unused (available) characters in the last SMS
     *       (int).
     *
     *   In addition to thoses keys, `extra' is defined (as an array) when the
     *   $extra argument is set to true:
     *   - extra: an array with:
     *     - message_utf8: The message argument converted in UTF-8.
     *     - encoding: 'GSM-7bit' or 'UCS-2'
     *     - SMS_total_bits: number of bits in a SMS.
     *     - SMS_UDH_bits: bits used for the UDH header (padding included). 0
     *         when no UDH header is needed.
     *     - SMS_payload_bits: bits available for the message in a SMS
     *         (SMS_total_bits reduced by SMS_UDH_bits).
     *     - message_payload_bits: bits used by the message.
     *     - message_total_bits: bits used by the message plus UDH bits when
     *         UDH is needed.
     *
     *     message_utf8 and encoding are repeated, so the `extra' array is
     *     self-sufficient.
     *
     *     SMS_total_bits is a constant in the GSM world (1120 bits) and is
     *     provided as helper.
     *
     *     When the message can be encoded into only one SMS, there is no need
     *     of supplementary header (UDH). In that case, we have
     *     SMS_payload_bits == SMS_total_bits and
     *     message_payload_bits == message_total_bits and
     *     SMS_UDH_bits == 0.
     */
    public static function message_infos($message, $extra=FALSE) {
        /*
         * GSM 7 bit Basic Character Set.
         *
         * This is the default alphabet for GSM where all character are
         * represented by 7 bits (septet) in respect of the GSM 03.38
         * (or 3GPP 23.038) standard.
         *
         * NOTE: While the ESC character is part of the Basic Character Set
         * (0x1b), it is used as prefix for the 7-bit extension mechanism (see
         * below). We do honor the ESC count by counting two characters for
         * those in the Basic Character Set Extension table.
         */
        //$GSM7bit_chars   = "@£\$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";
        $GSM7bit_chars   = "-@£\$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"; // https://bugs.php.net/bug.php?id=47229.

        /*
         * GSM 7 bit Basic Character Set Extension.
         *
         * Thoses characters are encoded by using two septet (the first being
         * ESC from the Basic Character Set).
         */
        $GSM7bit_exchars = "\x0c^{}\\[~]|€";

        /*
         * Regular expression to scan characters that belongs to the Basic
         * Character Set Extension table.
         */
        $GSM7bit_exregex = '/[' . preg_quote($GSM7bit_exchars, '/') . ']/u';

        /*
         * Regular expression to scan characters that will force to use UCS-2
         * instead of GSM-7bit. Basically every character except those in
         * either the Basic Character Set or the Basic Character Set Extension
         * will force UCS-2.
         */
        $UCS2_regex = '/[^' . preg_quote($GSM7bit_chars . $GSM7bit_exchars, '/') . ']/m';

        /*
         * Convert the message (payload) in UTF-8 if needed.
         */

        $m = $message;
        if (!No2SMS_Client::is_utf8($message))
            $m = utf8_encode($message);
        $mlen = mb_strlen($m, 'UTF-8');

        /*
         * detect which encoding is needed for the given message.
         */

        if (preg_match($UCS2_regex, $m)) {
            $encoding = 'UCS-2';
            $bpc = 16; // bits per character
        } else {
            $encoding = 'GSM-7bit';
            $bpc = 7; // bits per character
        }

        /*
         * Now that we know the message's encoding, compute how many bits are
         * needed to represent it.
         */
        $payload_bits = $bpc * $mlen;
        if ($encoding === 'GSM-7bit') {
            /*
             * characters from the Basic Character Set Extension are
             * represented with two septet, so we need to count them twice.
             */
            $payload_bits += $bpc * preg_match_all($GSM7bit_exregex, $m);
        }

        /*
         * Now we can compute how many SMS are needed in order to represent the
         * full message. If more than one SMS is needed, each SMS's first 48
         * bits are reserved by a User Data Header (UDH) used to concatenate
         * them, leaving only 1072 bits for the payload.
         */

        /* total bits per SMS including UDH (constant) */
        $SMS_bits = 140 * 8; // 1120 bits

        /*
         * A UDH header is added to each SMS if the message need to be
         * splitted into more than one SMS. It will effectively reduce the
         * number of bits available for the message for each SMS.
         *
         * UDH header's length is 48 bits. If needed (i.e. in the GSM-7bit
         * encoding), it will be padded with zeros at the start in order to be
         * aligned.
         */
        if ($payload_bits > $SMS_bits)
            $SMS_UDH_bits = $bpc * (int)ceil(48.0 / $bpc);
        else
            $SMS_UDH_bits = 0;
        /* reduce the number of bits available for the payload when we
            need UDH */
        $SMS_payload_bits = $SMS_bits - $SMS_UDH_bits;
        $sms = (int)ceil($payload_bits / $SMS_payload_bits);

        /* populate the return values */
        $data = array(
            'message_utf8' => $m,
            'encoding'     => $encoding,
            'SMS'          => $sms,
            'characters'   => (int)floor($payload_bits / $bpc),
            'remaining'    => (int)floor(($SMS_payload_bits * $sms - $payload_bits) / $bpc),
        );
        if ($extra) {
            /*
             * compute how many bits in total we need (message's total bits).
             * It is the bits needed for the message plus UDH bits (when the
             * message is splitted).
             */
            $total_bits = ($sms * $SMS_UDH_bits) + $payload_bits;

            /* fill in the extra array */
            $data['extra'] = array(
                /* message and encoding repeated */
                'message_utf8' => $m,
                'encoding'     => $encoding,
                /* constant */
                'SMS_total_bits' => $SMS_bits,
                /* depend on the encoding / message */
                'SMS_UDH_bits'         => $SMS_UDH_bits,
                'SMS_payload_bits'     => $SMS_payload_bits,
                'message_payload_bits' => $payload_bits,
                'message_total_bits'   => $total_bits,
            );
        }

        return $data;
    }

    /**
     * Test if a message contains characters that can not be represented in a
     * GSM SMS.
     *
     * @param $message (required)
     *   The message to analyze (string). As for send_message(), it is expected
     *   to be encoded in either ASCII, ISO-8859-1 or UTF-8.
     *
     * @return
     *   An array with the following keys:
     *   - message_utf8: The message argument converted in UTF-8.
     *   - valid: true if the message contains no invalid character, false
     *       otherwise.
     *   - message_sanitized: the message (in UTF-8) where all invalid
     *       characters where replaced by the `?' character. If an error
     *       occured (from preg_place()) NULL is returned.
     *
     *   When valid is true you can expect that message_sanitized and
     *   message_utf8 are the same.
     */
    public static function test_message_conversion($message) {
        $m = $message;
        if (!No2SMS_Client::is_utf8($message))
            $m = utf8_encode($message);
        /*
         * UCS-2 can only encode characters that belongs to Unicode's Plane 0,
         * the Basic Multilingual Plane. This regular expression, based on
         * http://w3.org/International/questions/qa-forms-utf-8.html, capture
         * each UTF-8 characters outside Unicode's Plane 0.
         *
         * @see No2SMS_Client::is_utf8
         */
        $utf8_to_ucs2_unsafe_regex = '%(
               \xF0[\x90-\xBF][\x80-\xBF]{2}     # planes 1-3
            | [\xF1-\xF3][\x80-\xBF]{3}          # planes 4-15
            |  \xF4[\x80-\x8F][\x80-\xBF]{2}     # plane 16
        )%xs';

        $ucount = 0; // unsafe character count
        $sanitized =
            preg_replace($utf8_to_ucs2_unsafe_regex, '?', $m, -1, $ucount);

        /* populate the return values */
        return array(
            'message_utf8'      => $m,
            'valid'             => ($ucount === 0),
            'message_sanitized' => $sanitized,
        );
    }
}

/**
 * Exception class thrown by No2SMS_Client.
 */
class No2SMS_Exception extends Exception { }
