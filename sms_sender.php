<?php
require_once(dirname(__FILE__) . '/No2SMS_Client.class.php');

/* affichage des informations avancées du message, nombre de SMS utilsés etc. 
var_dump(No2SMS_Client::message_infos($message, TRUE));
var_dump(No2SMS_Client::test_message_conversion($message));
*/

if(isset($_POST['action']) && $_POST['action'] == "valider")
{

    if((isset($_POST['destinataire']) && $_POST['destinataire'] != "") && (isset($_POST['contenu']) && $_POST['contenu'] != ""))
    {
        $destination = $_POST['destinataire'];
        $message = $_POST['contenu'];
        $credits = sendSms($message, $destination);
        header("Location: index.php?message=sent&credits=".$credits);
    }

    else{
        header("Location: index.php?message=error-fill");
    }
    
}



function sendSms($message, $destination){
    $user = 'devjob';
    $password = base64_decode("cG9vcmx5Y29kZWRwYXNzd29yZA==");

    /* on crée un nouveau client pour l'API */
    $client = new No2SMS_Client($user, $password);

    try {
        /* test de l'authentification */
        if (!$client->auth())
            die('mauvais utilisateur ou mot de passe');

        /* envoi du SMS */
        echo "===> ENVOI<br>";
        $res = $client->send_message($destination, $message);
        var_dump($res);
        $id = $res[0][2];
        echo "<br>SMS-ID: $id <br>";

        /* décommenter pour tester l'annulation */
        //print "===> CANCEL\n";
        //$res = $client->cancel_message($id);
        //var_dump($res);

        echo "===> STATUT<br>";
        $res = $client->get_status($id);
        var_dump($res);

        /* on affiche le nombre de crédits restant */
        $credits = $client->get_credits();
        return $credits;

    } catch (No2SMS_Exception $e) {
        echo "!!! Problème de connexion: ".$e->getMessage();
        exit(1);
        }
    
}