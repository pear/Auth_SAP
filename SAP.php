<?php
//
// +----------------------------------------------------------------------+
// | PHP Version 4                                                        |
// +----------------------------------------------------------------------+
// | Copyright (c) 1997-2003 The PHP Group                                |
// +----------------------------------------------------------------------+
// | This source file is subject to version 2.02 of the PHP license,      |
// | that is bundled with this package in the file LICENSE, and is        |
// | available at through the world-wide-web at                           |
// | http://www.php.net/license/2_02.txt.                                 |
// | If you did not receive a copy of the PHP license and are unable to   |
// | obtain it through the world-wide-web, please send a note to          |
// | license@php.net so we can mail you a copy immediately.               |
// +----------------------------------------------------------------------+
// | Authors: Hartmut Holzgraefe <hholzgra@php.net>                       |
// +----------------------------------------------------------------------+
//
// $Id$
//

require_once "Auth/Container.php";
require_once "PEAR.php";

/**
 * Storage driver for fetching login data from R/3 or mySAP
 *
 * This class provides user authentication against a SAP R/3 or mySAP Server
 * It binds to a SAP application server using a preconfigured user
 * that has to be able to perform calls to the SUSR_LOGIN_CHECK_RFC
 * and SO_USER_LIST_READ (for the listUsers() method) ABAP RFC functions.
 *
 * This class needs the saprfc extension installed which is available at
 * http://saprfc.sourceforge.net/
 * 
 * Required connection parameters are:
 * ASHOST: the application server to talk to
 * SYSNR : the system number on the application server
 * CLIENT: the client number on the application server
 * USER  : the user name to connect as
 * PASSWD: the users password
 *
 * Optional parameters include 
 * GWHOST, GWSERV, MSHOST, R3NAME, GROUP, LANG and TRACE.
 *
 * Additional information on the connection parameters are available at
 * http://saprfc.sourceforge.net/src/saprfc.html#function.saprfc-open.html
 * and in the original SAP RFC SDK documentation
 *
 * Sample usage:
 *
 * <?php
 * ...
 * // authenticate against a local Linux TestDrive installation
 *   $a = new Auth("SAP", array ("ASHOST" => "localhost",
 *                               "SYSNR"  => "17",
 *                               "CLIENT" => "000",
 *                               "USER"   => "SAP*",
 *                               "PASSWD" => "06071992");
 *
 * @author   Hartmut Holzgraefe <hholzgra@php.net>
 * @package  Auth
 * @version  $Revision$
 */
class Auth_Container_SAP extends Auth_Container
{
    /**
     * Options for the class
     * @var array
     */
    var $options = array();

    /**
     * Connection handle to SAP applicat
     * @var string
     */
    var $conn_id = false;

    /**
     * Constructor of the container class
     *
     * @param  $params, associative hash with connection info
     * @return object Returns an error object if something went wrong
     */
    function Auth_Container_SAP($params)
    {
		if (!extension_loaded("saprfc")) {
			return PEAR::raiseError("Auth_Container_SAP: saprfc extension not loaded", 41, PEAR_ERROR_DIE);
		}

        $this->_setDefaults();
		
        if (is_array($params)) {
            $this->_parseOptions($params);
        }
		
        return $this->_connect();
    }
	
    // }}}
    // {{{ _connect()
	
    /**
     * Connect to the LDAP server using the global options
     *
     * @access private
     * @return object  Returns a PEAR error object if an error occurs.
     */
    function _connect()
    {
		$this->conn_id = saprfc_open($this->options);
		
		if (!is_resource($this->conn_id)) {
			return PEAR::raiseError("Auth_Container_SAP: Could not connect to SAP server: ".saprfc_error(), 41, PEAR_ERROR_DIE);
		}

		return true;
    }

    // }}}
    // {{{ _setDefaults()

    /**
     * Set some default options
     *
     * @access private
     */
    function _setDefaults()
    {
		// these settings are suitable for the Linux TestDrive 
		// installed on localhost
		$this->options = array ("ASHOST" => "localhost",
								"SYSNR"  => "17",
								"CLIENT" => "000",
								"USER"   => "SAP*",
								"PASSWD" => "06071992");
    }

    /**
     * Parse options passed to the container class
     *
     * @access private
     * @param  array
     */ 
    function _parseOptions($array)
    {
        foreach ($array as $key => $value) {
            $this->options[$key] = $value;
        }
    }

    /**
     * Fetch data from SAP server
     *
     * Searches the SAP server for the given username
     * combination.
     *
     * @param  string Username
     * @param  string Password
     * @return boolean
     */
    function fetchData($username, $password)
    {     
		// discover function specs
		$fce = saprfc_function_discover($this->conn_id, "SUSR_LOGIN_CHECK_RFC");
		if (!$fce) {
			return PEAR::raiseError("Auth_Container_SAP: Could not get function info from SAP server: " . saprfc_error(), 41, PEAR_ERROR_DIE);
		}

		// set function parameters
		saprfc_import($fce, "BNAME"   ,$username);
		saprfc_import($fce, "PASSWORD",$password);

		// call function
		$rfc_rc = @saprfc_call_and_receive($fce);

		// release function specs
		saprfc_function_free($fce);

		// only the execution status matters here
		return $rfc_rc == SAPRFC_OK;
    }

    // {{{ listUsers()

    /**
     * List all SAP users available
	 *
	 * @return array
     */
    function listUsers()
    {
		// discover function specs
		$fce = saprfc_function_discover($rfc, "SO_USER_LIST_READ");
		if (!$fce) {
			return PEAR::raiseError("Auth_Container_SAP: Could not get function info from SAP server: " . saprfc_error(), 41, PEAR_ERROR_DIE);
		}

		// set function parameter
		saprfc_import($fce, "USER_GENERIC_NAME","*");

		// prepare table for returned results
		saprfc_table_init($fce, "USER_DISPLAY_TAB");

		// call function
		$rfc_rc = @saprfc_call_and_receive($fce);

		// error handling
		if ($rfc_rc != SAPRFC_OK) {
			return PEAR::raiseError("Auth_Container_SAP: Could not fecth userlist from SAP server: " . saprfc_error(), 41, PEAR_ERROR_DIE);
		}

		// fetch users from returned table
		$users = array();
		$rows = saprfc_table_rows($fce, "USER_DISPLAY_TAB");
		for ($i = 1; $i <= $rows; $i++) {
			$row = saprfc_table_read($fce, "USER_DISPLAY_TAB", $i);
			if (empty($row["USRNAM"])) {
			    continue;
			}
			$users[] = $row;
		}

		// release functions specs
		saprfc_function_free($fce);

		// return result;
		return $users;
	}

    // }}}
}
/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
?>
