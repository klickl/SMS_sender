<?php
	require_once(dirname(__FILE__) . '/No2SMS_Client.class.php');
  
  function getClient()
  {
  	$user = 'devjob';
    $password = base64_decode("cG9vcmx5Y29kZWRwYXNzd29yZA==");
  	return new No2SMS_Client($user, $password);
  }

  function getCredits(){
  	return getClient()->get_credits();
  }

  function sendSms($message, $destination){

    $client = getClient();

    try {
        /* test de l'authentification */
        if (!$client->auth())
            die('mauvais utilisateur ou mot de passe');

        /* envoi du SMS */
        $res = $client->send_message($destination, $message);      

    } catch (No2SMS_Exception $e) {
        echo "Problème de connexion: ".$e->getMessage();
        exit(1);
    }
    
}