<?php

namespace Guiyomh\Bundle\GoogleAuthenticatorBundle\Model;

/**
 * Description of GoogleAuthenticatorUserInterface
 *
 * @author gcamus
 */
interface GoogleAuthenticatorUserInterface
{

    /**
     * @return string
     */
    public function getTwoStepVerificationCode();

    /**
     * @param string $code
     *
     * @return string
     */
    public function setTwoStepVerificationCode($code);
}

