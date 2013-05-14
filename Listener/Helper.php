<?php

namespace Guiyomh\Bundle\GoogleAuthenticatorBundle\Listener;

use Google\Authenticator\GoogleAuthenticator as BaseGoogleAuthenticator;
use Guiyomh\Bundle\GoogleAuthenticatorBundle\Model\GoogleAuthenticatorUserInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

class Helper
{

    protected $server;
    protected $authenticator;

    /**
     * @param $server
     * @param \Google\Authenticator\GoogleAuthenticator $authenticator
     */
    public function __construct($server, BaseGoogleAuthenticator $authenticator)
    {
        $this->server = $server;
        $this->authenticator = $authenticator;
    }

    /**
     * @param \Sonata\UserBundle\Model\GoogleAuthenticatorUserInterface $user
     * @param $code
     * @return bool
     */
    public function checkCode(GoogleAuthenticatorUserInterface $user, $code)
    {
        return $this->authenticator->checkCode($user->getTwoStepVerificationCode(), $code);
    }

    /**
     * @param \Sonata\UserBundle\Model\GoogleAuthenticatorUserInterface $user
     * @return string
     */
    public function getUrl(GoogleAuthenticatorUserInterface $user)
    {
        return $this->authenticator->getUrl($user->getUsername(), $this->server, $user->getTwoStepVerificationCode());
    }

    /**
     * @return string
     */
    public function generateSecret()
    {
        return $this->authenticator->generateSecret();
    }

    /**
     * @param \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken $token
     * @return string
     */
    public function getSessionKey(UsernamePasswordToken $token)
    {
        return sprintf('oxy_core_google_authenticator_%s_%s', $token->getProviderKey(), $token->getUsername());
    }

}