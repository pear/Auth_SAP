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
        $this->_setDefaults();

        if (is_array($params)) {
            $this->_parseOptions($params);
        }

        $this->_connect();

        return true;
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

			if (!is_resource($this->con_id)) {
				return PEAR::raiseError("Auth_Container_PHP: Could not connect to SAP server: ".saprfc_error(), 41, PEAR_ERROR_DIE);
			}
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
     * @return boolean
     */
    function fetchData($username, $password)
    {      
			$fce = saprfc_function_discover($this->conn_id, "SUSR_LOGIN_CHECK_RFC");
			if(!$fce) {
				return PEAR::raiseError("Auth_Container_PHP: Could not get function info from SAP server: ".saprfc_error(), 41, PEAR_ERROR_DIE);
			}
		
			saprfc_import ($fce,"BNAME"   ,$username);
			saprfc_import ($fce,"PASSWORD",$password);
			
			$rfc_rc = saprfc_call_and_receive ($fce);
			
			saprfc_function_free($fce);
			
			return $rfc_rf == SAPRFC_OK;
    }


    // {{{ listUsers()

    /**
     * List all SAP users available
		 *
		 * 
     */
    function listUsers()
    {
			$users = array();

			$fce = saprfc_function_discover($rfc, "SO_USER_LIST_READ");
			if(!$fce) {
				return PEAR::raiseError("Auth_Container_PHP: Could not get function info from SAP server: ".saprfc_error(), 41, PEAR_ERROR_DIE);
			}
			
			saprfc_import ($fce, "USER_GENERIC_NAME","*");
			saprfc_table_init ($fce, "USER_DISPLAY_TAB");
			
			$rfc_rc = saprfc_call_and_receive ($fce);
			
			if($rfc_rc != SAPRFC_OK) {
				return PEAR::raiseError("Auth_Container_PHP: Could not fecth userlist from SAP server: ".saprfc_error(), 41, PEAR_ERROR_DIE);
			}

			$rows = saprfc_table_rows ($fce, "USER_DISPLAY_TAB");
			for ($i=1; $i<=$rows; $i++) {
				$row = saprfc_table_read ($fce, "USER_DISPLAY_TAB", $i);
				if(empty($row["USRNAM"])) continue;
				$users[] = $row;
			}
			
			
			saprfc_function_free($fce);
    }

    // }}}

}

?>
