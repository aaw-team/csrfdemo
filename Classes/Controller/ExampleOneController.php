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
 * This actioncontroller runs the csrf validation "by hand" in every
 * action method it is needed.
 */
class ExampleOneController extends AbstractController
{
    /**
     * @param array $data
     */
    public function createAction(array $data)
    {
        if (!$this->csrfValidation(false)) {
            // Add a message and redirect to errorAction
            $this->addFlashMessage('CSRF token validation failed', 'Security alert', \TYPO3\CMS\Core\Messaging\AbstractMessage::ERROR);
            $this->redirect('error');
            die();
        }

        // At this point we can be sure that the request is legitimate
    }
}
