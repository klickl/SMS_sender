<?php
require_once(dirname(__FILE__) . '/No2SMS_Client.class.php');

/* on test le nombre d'arguments */
if ($argc != 5) {
    /* affiche un message d'aide et termine le script */
    print "usage: php example.php user password destination message\n";
    exit(1);
}

$user        = $argv[1];
$password    = $argv[2];
$destination = $argv[3];
$message     = $argv[4];

/* affichage des informations avancées du message, nombre de SMS utilsés etc. */
var_dump(No2SMS_Client::message_infos($message, TRUE));
var_dump(No2SMS_Client::test_message_conversion($message));

/* on crée un nouveau client pour l'API */
$client = new No2SMS_Client($user, $password);

try {
    /* test de l'authentification */
    if (!$client->auth())
        die('mauvais utilisateur ou mot de passe');

    /* envoi du SMS */
    print "===> ENVOI\n";
    $res = $client->send_message($destination, $message);
    var_dump($res);
    $id = $res[0][2];
    printf("SMS-ID: %s\n", $id);

    /* décommenter pour tester l'annulation */
    //print "===> CANCEL\n";
    //$res = $client->cancel_message($id);
    //var_dump($res);

    print "===> STATUT\n";
    $res = $client->get_status($id);
    var_dump($res);

    /* on affiche le nombre de crédits restant */
    $credits = $client->get_credits();
    printf("===> Il vous reste %d crédits\n", $credits);

} catch (No2SMS_Exception $e) {
    printf("!!! Problème de connexion: %s", $e->getMessage());
    exit(1);
}
