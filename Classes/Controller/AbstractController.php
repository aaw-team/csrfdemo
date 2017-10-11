<?php
declare(strict_types=1);
namespace AawTeam\CsrfDemo\Controller;

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

use AawTeam\CsrfDemo\Session\CsrfRegistry;
use AawTeam\CsrfDemo\ViewHelpers\Form\CsrfTokenViewHelper;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 *
 */
abstract class AbstractController extends \TYPO3\CMS\Extbase\Mvc\Controller\ActionController
{
    /**
     * @var bool
     */
    protected $enableExperimentalRequestMapping = false;

    /**
     * Experimental parent method extension: check the csrf protection
     * in request (if needed) before continuing. It gets called *before*
     * any arguments get processed.
     *
     * Any action method can add a @csrfvalidation annotation to its
     * phpdoc comment:
     *
     * @csrfvalidation (without further info):
     *
     *     Validate CSRF token every time the method is called
     *
     * @csrfvalidation ifArgumentsPassed(argumentName [, argumentName2 ...])
     *
     *     Validate CSRF token every time when the request contains at
     *     least one of the specified arguments. This makes only sense
     *     when arguments are optional.
     *
     * @see \TYPO3\CMS\Extbase\Mvc\Controller\AbstractController::mapRequestArgumentsToControllerArguments()
     */
    protected function mapRequestArgumentsToControllerArguments()
    {
        if ($this->enableExperimentalRequestMapping === true) {
            // Check only 'web' requests
            if ($this->request instanceof \TYPO3\CMS\Extbase\Mvc\Web\Request) {
                // Check for the @csrfvalidation annotation of the actionMethod
                // Possible specifications:
                // @csrfvalidation                                             Validate every time the actionMethod is called
                // @csrfvalidation ifArgumentsPassed(argument1 [, argument2])  Validate only if one of the arguments is passed in request
                $methodTagsValues = $this->reflectionService->getMethodTagsValues(get_class($this), $this->actionMethodName);
                if (array_key_exists('csrfvalidation', $methodTagsValues)) {
                    $specification = $methodTagsValues['csrfvalidation'];
                    $runValidation = false;
                    if (empty($specification)) {
                        $runValidation = true;
                    } elseif (strpos($specification[0], 'ifArgumentsPassed') !== false) {
                        $matches = [];
                        if (!preg_match('/^ifArgumentsPassed\\(([^\\)]+)\\)$/', $specification[0], $matches) || !isset($matches[1])) {
                            throw new \RuntimeException('Invalid @csrfvalidation annotation in ' . get_class($this) . '->' . $this->actionMethodName . '()');
                        }
                        $argumentsToCheck = GeneralUtility::trimExplode(',', $matches[1], true);
                        array_walk($argumentsToCheck, function(&$value, $key){
                            if (strpos($value, '$') === 0) {
                                $value = substr($value, 1);
                            }
                        });

                        foreach ($argumentsToCheck as $name) {
                            if ($this->request->hasArgument($name)) {
                                $runValidation = true;
                                break;
                            }
                        }
                    }

                    if ($runValidation) {
                        $this->csrfValidation();
                    }
                }
            }
        }

        return parent::mapRequestArgumentsToControllerArguments();
    }

    /**
     * @param bool $stopOnFailure
     * @throws \TYPO3\CMS\Extbase\Mvc\Exception\StopActionException
     * @return boolean
     */
    protected function csrfValidation(bool $stopOnFailure = true) : bool
    {
        $isValid = false;
        if ($this->request->hasArgument(CsrfTokenViewHelper::TOKEN_ID_IDENTIFIER)
            && $this->request->hasArgument(CsrfTokenViewHelper::TOKEN_VALUE_IDENTIFIER)
        ) {
            /** @var CsrfRegistry $csrfRegistry */
            $csrfRegistry = GeneralUtility::makeInstance(CsrfRegistry::class);
            $identifier = $this->request->getArgument(CsrfTokenViewHelper::TOKEN_ID_IDENTIFIER);
            $token = $this->request->getArgument(CsrfTokenViewHelper::TOKEN_VALUE_IDENTIFIER);
            if($csrfRegistry->verifyToken($identifier, $token)) {
                // Remove the arguments from the request
                $requestArguments = $this->request->getArguments();
                unset($requestArguments[CsrfTokenViewHelper::TOKEN_ID_IDENTIFIER]);
                unset($requestArguments[CsrfTokenViewHelper::TOKEN_VALUE_IDENTIFIER]);
                $this->request->setArguments($requestArguments);
                $isValid = true;
            }
        }

        if ($isValid === true) {
            return true;
        } elseif ($stopOnFailure === false) {
            return false;
        }

        $this->response->setContent('Security alert: CSRF token validation failed');
        throw new \TYPO3\CMS\Extbase\Mvc\Exception\StopActionException();
    }
}
