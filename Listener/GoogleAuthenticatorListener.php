<?php

namespace Guiyomh\Bundle\GoogleAuthenticatorBundle\Listener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Guiyomh\Bundle\GoogleAuthenticatorBundle\Model\GoogleAuthenticatorUserInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Templating\EngineInterface;
use Guiyomh\Bundle\GoogleAuthenticatorBundle\Listener\Helper;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;

/**
 * Description of GoogleAuthenticatorListener
 *
 * @author gcamus
 */
class GoogleAuthenticatorListener implements EventSubscriberInterface
{

    /**
     *
     * @var Symfony\Component\Security\Core\SecurityContextInterface
     */
    private $securityContext;

    /**
     *
     * @var Symfony\Component\Templating\EngineInterface
     */
    private $templating;
    
    /**
     *
     * @var string
     */
    private $template;

    /**
     *
     * @var Oxy\Bundle\CoreBundle\Listener\Helper
     */
    private $helper;

    public function __construct(Helper $helper, SecurityContextInterface $securityContext, EngineInterface $templating, $template)
    {
        $this->helper = $helper;
        $this->securityContext = $securityContext;
        $this->templating = $templating;
        $this->template = $template;
    }

    /**
     * {@inherit}
     */
    public static function getSubscribedEvents()
    {
        return array(
            SecurityEvents::INTERACTIVE_LOGIN => array(
                array('onSecurityInteractiveLogin', 0),
            ),
            KernelEvents::REQUEST => array(
                array('onCoreRequest', -1)
            )
        );
    }

    /**
     * @param \Symfony\Component\Security\Http\Event\InteractiveLoginEvent $event
     * @return
     */
    public function onSecurityInteractiveLogin(InteractiveLoginEvent $event)
    {

        if (!$event->getAuthenticationToken() instanceof UsernamePasswordToken) {
            return;
        }

        $token = $event->getAuthenticationToken();
        if (!$token->getUser() instanceof GoogleAuthenticatorUserInterface) {
            return;
        }

        if (!$token->getUser()->getTwoStepVerificationCode()) {
            return;
        }
        $event->getRequest()->getSession()->set($this->helper->getSessionKey($token), null);
    }

    /**
     * @param \Symfony\Component\HttpKernel\Event\GetResponseEvent $event
     * @return
     */
    public function onCoreRequest(GetResponseEvent $event)
    {
        $token = $this->securityContext->getToken();
        if (!$token) {
            return;
        }

        if (!$token instanceof UsernamePasswordToken) {
            return;
        }

        $key = $this->helper->getSessionKey($this->securityContext->getToken());
        $request = $event->getRequest();
        $session = $event->getRequest()->getSession();
        $user = $this->securityContext->getToken()->getUser();
        $url = $this->helper->getUrl($user);

//        if (!$session->has($key)) {
//            return;
//        }

        if ($session->get($key) === true) {
            return;
        }

        $state = 'init';
        if ($request->getMethod() == 'POST') {
            $result = $this->helper->checkCode($user, $request->get('_code'));
            if ($result == true) {
                $session->set($key, true);
                return;
            }
            $state = 'error';
        }

        $event->setResponse($this->templating->renderResponse($this->template, array(
                    'state' => $state, 'url' => $url
        )));
    }

}

