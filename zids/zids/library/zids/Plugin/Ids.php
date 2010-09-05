<?php
/*
		-------------------------------------------------------
		!   ZIDS = Zend Framework Intruder Detection System   !
		-------------------------------------------------------

Requirements: Zend Framework (tested with version 1.10)
			  PHP-IDS (tested with version 0.6.4)
			           Copyright (c) 2008 PHPIDS group (http://php-ids.org)
						  

						  Copyright (c) 2010
						 by Christian KONCILIA

						http://www.web-punk.com

All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
 * ZIDS (Zend Framework Intruder Detection System). Uses PHPIDS to detect intruders on your
 * website developed with Zend Framework. 
 *
 * @package    ZIDS
 * @author     Christian Koncilia
 * @copyright  Copyright (c) 2010 Christian Koncilia. (http://www.web-punk.com)
 * @license    New BSD License (see above)
 * @version    V.0.4 
 */
class ZIDS_Plugin_Ids extends Zend_Controller_Plugin_Abstract 
{
	private $_log = null;
	private $_email = null;	
	private $_levels;
	private $_logitems;
	private $_aggregate = false;
	private $_config;
	
	/**
	 * Constructor
	 *
	 * @param array|Zend_Config $config
	 * @param array (optional) $options. Valid options are 'log' (Zend_Log), 'email' (Zend_Mail)  
	 * @return void
	 */
	public function __construct(array $config, array $options = null) {
		$this->_config = $config;
		
		// analyze options set
		if (isset($options)) {
			if (array_key_exists('log', $options)) {
				$this->setLog($options['log']);
			}
			if (array_key_exists('email', $options)) {
				$this->setEmail($options['email']);
			}
		}
		
		// get options for unlikely-level
		if (0 >= intval($config['level']['unlikely']['upto'])) {
			throw new Exception('Upper bounds for unlikely-level has to be greater than zero!');
		}
		$this->_levels['unlikely']['upto'] = intval($config['level']['unlikely']['upto']);
		$this->_levels['unlikely']['action'] = explode(',', $config['level']['unlikely']['action']);
		
		// get options for likely-level
		if (intval($config['level']['likely']['upto']) <= intval($config['level']['unlikely']['upto'])) {
			throw new Exception('Upper bounds for likely-level has to be greater than upper bounds for unlikely-level!');
		}		
		$this->_levels['likely']['upto'] = intval($config['level']['likely']['upto']);
		$this->_levels['likely']['action'] = explode(',', $config['level']['likely']['action']);
		
		// get options for verylikely-level
		if (intval($config['level']['verylikely']['upto']) <= intval($config['level']['likely']['upto'])) {
			throw new Exception('Upper bounds for verylikely-level has to be greater than upper bounds for likely-level!');
		}
		$this->_levels['verylikely']['upto'] = intval($config['level']['verylikely']['upto']);
		$this->_levels['verylikely']['action'] = explode(',', $config['level']['verylikely']['action']);
		
		// get options for attack-level
		$this->_levels['attack']['action'] = explode(',', $config['level']['attack']['action']);
		
		// in case of a potential attack: what should ZIDS log?
		$this->_logitems = explode(',', $this->_config['log']['items']);
		array_walk($this->_logitems, create_function('&$arr','$arr=trim($arr);'));
		
		// should ZIDS aggregate all impacts in the session
		$this->_aggregate = $config['aggregate_in_session']; 
	}
	
	/**
	 * Register ZIDS plugin in the pre-Dispatch phase. 
	 * @param Zend_Controller_Request_Abstract $request
	 */
	public function preDispatch(Zend_Controller_Request_Abstract $request)
    {
    	// should ZIDS ignore this request?
		foreach ($this->_config['ignore']['requests']['module'] as $i => $module) {
			if ($request->getModuleName() == $module && 
				$request->getControllerName() == $this->_config['ignore']['requests']['controller'][$i] &&
				$request->getActionName() == $this->_config['ignore']['requests']['action'][$i])
				return $request;
		}

		require_once 'IDS/Init.php';
		
		$input = array ('REQUEST' => $_REQUEST, 
						'GET' => $_GET, 
						'POST' => $_POST, 
						'COOKIE' => $_COOKIE );
		$init = IDS_Init::init ( $this->_config['phpids']['config'] );

		$ids = new IDS_Monitor ( $input, $init );
		$result = $ids->run ();

		if (! $result->isEmpty ()) {
			// get PHP-IDS impact
			$impact = $result->getImpact();
			
			// check, if ZIDS should aggregate all impacts in the session			
			if ($this->_aggregate) {
				$session = new Zend_Session_Namespace('ZIDS');
				$impact += $session->impact;
				$session->impact = $impact;
			}
			
			// check, ZIDS level of attack?
			if ($impact <= $this->_levels['unlikely']['upto']) {
				$level = 'unlikely';
			} else if ($impact <= $this->_levels['likely']['upto']) {
				$level = 'likely';
			} else if ($impact <= $this->_levels['verylikely']['upto']) {
				$level = 'verylikely';
			} else {
				$level = 'attack';
			}

			// which actions should ZIDS perform?
			$actions = $this->_levels[$level]['action'];
			// make sure to trim each action, e.g. ' email' => 'email'
			array_walk($actions, create_function('&$arr','$arr=trim($arr);')); 
			
			// do we have to ignore this (potential) attack?
			if (!in_array('ignore', $actions)) {
				$notification = $this->getNotificationString($impact, $result, $level); 
				if (in_array('log', $actions)) {
					if ($this->_log == null) {
						throw new Exception('ZIDS cannot use the log action unless you register a Zend_Log instance. Use the options array in the constructor or the setLog methode.');
					}
					$this->_log->log($notification, Zend_Log::ALERT);
				}
				if (in_array('email', $actions)) {
					$this->sendMail($notification);
				}
				if (in_array('redirect', $actions)) {
					$request->setModuleName( $this->_config['redirect']['module'] );
					$request->setControllerName( $this->_config['redirect']['controller'] );
					$request->setActionName( $this->_config['redirect']['action'] );
				}
			}			
		}
		return $request;    	
    }
    
    /**
     * Assembles the notification string
     * @param int $impact Impact of the potential attack
     * @param IDS_Report $result the result of PHPIDSs check
     * @param string $level the level of the potential attack
     * @return string the assembled notification
     */
    private function getNotificationString($impact, $result, $level) {
    	$retstr = "ZIDS detected a potential attack! ZIDS LEVEL: " . $level;
    	foreach ($this->_logitems as $item) {
 		   	switch ($item) {
    			case "ip":
        			$retstr .= " from IP: " . $_SERVER['REMOTE_ADDR'];
        			break;
    			case "impact":
        			$retstr .= " Impact: " . $impact;
        			break;
    			case "tags":
        			$retstr .= " Tags: " . implode(',', $result->getTags());
        			break;
    			case "variables":
        			$retstr .= " Variables: ";
        			foreach ($result->getIterator() as $event) {
        				$retstr .= $event->getName() . " (Tags: " . $event->getTags() . "; Value: " . $event->getValue() . "; Impact: " . $event->getImpact() . ") ";
        			}
        			break;
 		   	}
    	}
    	return $retstr;
    }
	
    /**
     * Sends an email notification to the admin in case of a potential attack
     * @param string $notification the emails text
     * @return void
     */
    private function sendMail($notification) {
    	// if email has not been set using the constructor, 
    	// try to fetch parameters from the application.ini
    	if ($this->_email == null) {
			$config = array(
					'ssl' => $this->_config['email']['smtp']['ssl'], 
					'port' => $this->_config['email']['smtp']['port'],
					'auth' => $this->_config['email']['smtp']['auth'],
    	            'username' => $this->_config['email']['smtp']['username'],
	                'password' => $this->_config['email']['smtp']['password']);
			$transport = new Zend_Mail_Transport_Smtp(
							$this->_config['email']['smtp']['host'],
							$config);
			$mail = new Zend_Mail('UTF-8');

			// setze Empfänger und Absender		
			$mail->setFrom($this->_config['email']['from'], 'ZIDS Notification');
			$mail->addTo($this->_config['email']['to']);
    	} else {
    		$mail = $this->_email;
    	}

    	// setzte Email Text & subject
		$mail->setBodyHtml( $notification );
		$mail->setBodyText( $notification );
		$mail->setSubject( 'ZIDS Notification: potential attack on your website' );
    	
		$mail->send( (isset($transport)?$transport:null) );
    }
    
	/**
	 * @return the $_log
	 */
	public function getLog() {
		return $this->_log;
	}

	/**
	 * @param $_log the $_log to set
	 */
	public function setLog($log) {
		if (!is_a($log, 'Zend_Log')) {
			throw new Exception('log-object provided is not of type Zend_Log!');
		}
		$this->_log = $log;
	}

	/**
	 * @return the $_email
	 */
	public function getEmail() {
		return $this->_email;
	}

	/**
	 * @param $_email the $_email to set
	 */
	public function setEmail($email) {
		if (!is_a($email, 'Zend_Mail')) {
			throw new Exception('email-object provided is not of type Zend_Mail!');
		}
		$this->_email = $email;
	}
}
