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

/**
 * This actioncontroller uses the experimental feature that uses the
 * phpDoc annotations.
 */
class ExampleTwoController extends AbstractController
{
    /**
     * @var bool
     */
    protected $enableExperimentalRequestMapping = true;

    /**
     * @param array $data
     * @csrfvalidation
     */
    public function createAction(array $data)
    {
        // At this point we can be sure that the request is legitimate
    }

    /**
     * @param array $data
     * @csrfvalidation ifArgumentsPassed(confirmation)
     */
    public function deleteAction(int $productId, bool $confirmation = false)
    {
        if ($confirmation !== true) {
            $this->addFlashMessage('You must check the confirmation checkbox', 'Error', \TYPO3\CMS\Core\Messaging\AbstractMessage::ERROR);
            return;
        }
        // At this point we can be sure that the request is legitimate
    }

    /**
     *
     * @param \TYPO3\CMS\Extbase\Domain\Model\FrontendUser $frontendUser
     * @csrfvalidation ifArgumentsPassed(frontendUser)
     */
    public function createUserAction(\TYPO3\CMS\Extbase\Domain\Model\FrontendUser $frontendUser = null)
    {
        if (!$frontendUser) {
            // Display the form
        }
        // At this point we can be sure that the request is legitimate
    }
}
