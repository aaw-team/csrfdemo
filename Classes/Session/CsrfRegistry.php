<?php
namespace AawTeam\CsrfDemo\Session;

/*
 * Copyright 2017 Agentur am Wasser | Maeder & Partner AG
 *
 * This file is part of the TYPO3 CMS project.
 *
 * It is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, either version 2
 * of the License, or any later version.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 * The TYPO3 project - inspiring people to share!
 */

use ParagonIE\ConstantTime\Encoding;
use TYPO3\CMS\Core\Authentication\AbstractUserAuthentication;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Crypto\Random;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Frontend\Authentication\FrontendUserAuthentication;

/**
 *
 * @author chrigu
 *
 */
final class CsrfRegistry
{
    const SESSION_IDENTIFIER = '__MCI_CSRF__';
    const TOKEN_LIFETIME = 1800;
    const MAX_TOKENS_IN_SESSION = 25;

    /**
     * @var AbstractUserAuthentication
     */
    private $userAuthentication;

    /**
     * @throws \RuntimeException
     * @return void
     */
    public function __construct()
    {
        if (TYPO3_MODE === 'FE' && is_object($GLOBALS['TSFE']) && ($GLOBALS['TSFE']->fe_user instanceof FrontendUserAuthentication) && isset($GLOBALS['TSFE']->fe_user->user['uid'])) {
            $this->userAuthentication = $GLOBALS['TSFE']->fe_user;
        } elseif (TYPO3_MODE === 'BE' && isset($GLOBALS['BE_USER']) && ($GLOBALS['BE_USER'] instanceof BackendUserAuthentication) && isset($GLOBALS['BE_USER']->user['uid'])) {
            $this->userAuthentication = $GLOBALS['BE_USER'];
        } else {
            throw new \RuntimeException('Invalid environment');
        }
    }

    /**
     * @return void
     */
    public function clearAll()
    {
        $this->storeSessionData([]);
    }

    /**
     * @return array
     */
    public function generateTokenAndIdentifier() : array
    {
        $identifier = Encoding::hexEncode(GeneralUtility::makeInstance(Random::class)->generateRandomBytes(16));
        $token = [
            'token' => Encoding::hexEncode(GeneralUtility::makeInstance(Random::class)->generateRandomBytes(32)),
            'crdate' => (int) $GLOBALS['EXEC_TIME'],
        ];
        $this->storeToken($identifier, $token);
        return [$identifier, $token['token']];
    }

    /**
     *
     * @param string $identifier
     * @param string $tokenFromUserInput
     * @throws \InvalidArgumentException
     * @return boolean
     */
    public function verifyToken(string $identifier, string $tokenFromUserInput) : bool
    {
        if (empty($identifier) || preg_match('/[^0-9a-f]/i', $identifier)) {
            throw new \InvalidArgumentException('$identifier must be not empty string containing hex-characters only');
        }

        $sessionData = $this->getSessionData();
        if (!array_key_exists($identifier, $sessionData)) {
            return false;
        }

        // Retrieve token from session data
        $token = $sessionData[$identifier];

        // Directly remove token from session data
        unset($sessionData[$identifier]);
        $this->storeSessionData($sessionData);

        // Check token
        if (!$this->isValidToken($token)) {
            return false;
        }

        return \hash_equals($token['token'], $tokenFromUserInput);
    }

    /**
     * @param string $identifier
     * @param array $token
     */
    private function storeToken(string $identifier, array $token)
    {
        $sessionData = $this->getSessionData();
        // Remove invalid/outdated tokens
        $sessionData = array_filter($sessionData, [$this, 'isValidToken']);
        $sessionData[$identifier] = $token;

        // Remove exceeding tokens from session
        if (count($sessionData) > self::MAX_TOKENS_IN_SESSION) {
            uasort($sessionData, function($a, $b){
                if ($a['crdate'] == $b['crdate']) {
                    return 0;
                }
                return ($a['crdate'] > $b['crdate']) ? -1 : 1;
            });
            while(count($sessionData) > self::MAX_TOKENS_IN_SESSION) {
                array_pop($sessionData);
            }
        }
        $this->storeSessionData($sessionData);
    }

    /**
     * @param array $sessionData
     */
    private function storeSessionData(array $sessionData)
    {
        $this->userAuthentication->setAndSaveSessionData(self::SESSION_IDENTIFIER, \json_encode($sessionData));
    }

    /**
     * @return array
     */
    private function getSessionData() : array
    {
        $sessionData = $this->userAuthentication->getSessionData(self::SESSION_IDENTIFIER);
        if (is_string($sessionData) && !empty($sessionData)) {
            $sessionData = \json_decode($sessionData, true);
        }
        if (!is_array($sessionData)) {
            $sessionData = [];
        }
        return $sessionData;
    }

    /**
     * @param array $token
     * @return boolean
     */
    private function isValidToken(array $token) : bool
    {
        return is_array($token)
               && array_key_exists('crdate', $token) && is_int($token['crdate'])
               && array_key_exists('token', $token) && is_string($token['token'])
               && $token['crdate'] >= ($GLOBALS['EXEC_TIME'] - self::TOKEN_LIFETIME);
    }

}
