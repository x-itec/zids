        -------------------------------------------------------
		!   ZIDS = Zend Framework Intruder Detection System   !
		-------------------------------------------------------

   Requirements: Zend Framework (tested with version 1.10)
	    		 PHP-IDS (tested with version 0.6.4)
						  

						  Copyright (c) 2010
						 by Christian KONCILIA

						http://www.web-punk.com

1) LICENCE
----------
See \library\zids\Plugin\Ids.php for licence information.

2) VERSION
----------
This is ZIDS Version 0.4.0

3) WHAT IS ZIDS
---------------
ZIDS uses PHP-IDS to analyze each request. The impact of a request is 
an integer value returned by PHP-IDS that indicates indicates the severity 
of the attack. The higher the impact, the more likely the request was an attack!

ZIDS enables you to easily integrate PHP-IDS in your Zend Framework project. It 
allows you to define different levels of attack: 'unlikely', 'likely', 
'very likely' and 'attack'.

For each level you may define:
  - an interval that defines how the impact will be categorized, e.g. impact 
    0-10 will be considered as 'unlikely' attack.
  - how to deal with an attack, e.g. ignore the attack, log the attack, send 
    an email to the admin, or redirect the user to a special side (controller/action)

Furthermore, you may enable to aggregate all impacts in your session. This is useful 
as usually an attacker will start to analyze your website with a series of "small" 
attacks, i.e. attacks with an impact below 15. If you enable aggregation, four attacks 
with an impact of 5 will aggregate to an attack with an impact of 20 (5 + 5 + 5 + 5).

4) INSTALLING ZIDS
------------------
   a) Download the ZIDS code
   b) Download PHP-IDS (http://php-ids.org/). ZIDS has been tested with PHP-IDS 0.6.4
   c) Extract and copy the PHP-IDS code to your project's \library folder, e.g. \library\phpids-0.6.4
   d) Open \library\phpids-0.6.4\lib\IDS\Config\Config.ini.php! Set base_path to your IDS folder
      and enable use_base_path, e.g.
         base_path       = "C:/Programs/Zend/Apache2/htdocs/myproject/library/phpids-0.6.4/lib/IDS/"
         use_base_path   = true
   e) Extract and copy the ZIDS code to your project's \library folder, e.g. \library\zids\Plugin\Ids.php
   f) Adopt your application.ini file (see \zids\application\config\application.ini for a sample 
      configuration)
   g) Adopt your bootstrap.php file (see next chapter)
   
5) REGISTER THE ZIDS PLUGIN
---------------------------
Copy and paste the following source into your bootstrap.php file:

    protected function _initZIDS() {
        // Setup autoloader with namespace
        $autoloader = Zend_Loader_Autoloader::getInstance();
        $autoloader->registerNamespace('ZIDS');
        
        // Ensure the front controller is initialized
        $this->bootstrap('FrontController');

        // Retrieve the front controller from the bootstrap registry
        $front = $this->getResource('FrontController');

        // Only enable zfdebug if options have been specified for it
        if ($this->hasOption('zids'))
        {
            // Create ZIDS instance
            $zids = new ZIDS_Plugin_Ids($this->getOption('zids'));

            // create a logger 
			$logger = new Zend_Log ();
			$filter = new Zend_Log_Filter_Priority(Zend_Log::ERR);
			$writer = new Zend_Log_Writer_Stream ("../data/logs/log.txt");
			$logger->addWriter ( $writer );

			// register logger within ZIDS
            $zids->setLog($logger);
			
            // Register ZIDS with the front controller
            $front->registerPlugin($zids);
        }
    }
    
6) BOOTSTRAP OPTIONS
--------------------
The bootstrap code in chapter 5 is only an example of how you may register the ZIDS plugin in 
your bootstrap.

You may also pass an options array to the constructor of ZIDS_Plugin_Ids. Valid options are 
'log' and 'email', where log specifies a Zend_Log instance and email specifies a Zend_Mail 
instance that ZIDS should use to log possible attacks and to send emails about possible attacks.

This means you may also use the following code to create an instance of ZIDS:

    // Create ZIDS instance
    $zids = new ZIDS_Plugin_Ids($this->getOption('zids'), 
                                array('log' => $logger, 
                                      'email' => $mail));
                                      
Where $logger is an instance of Zend_Log and $mail is an instance of Zend_Mail

 
                                


   



