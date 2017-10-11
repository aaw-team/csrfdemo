<?php
declare(strict_types=1);
namespace AawTeam\CsrfDemo\ViewHelpers\Form;

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
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 *
 * @author chrigu
 *
 */
class CsrfTokenViewHelper extends \TYPO3\CMS\Fluid\ViewHelpers\Form\AbstractFormFieldViewHelper
{
    const TOKEN_ID_IDENTIFIER = 'CSRF_TOKENID';
    const TOKEN_VALUE_IDENTIFIER = 'CSRF_TOKEN';

    /**
     * @return string
     */
    public function render()
    {
        /** @var CsrfRegistry $csrfRegistry */
        $csrfRegistry = GeneralUtility::makeInstance(CsrfRegistry::class);
        list($identifier, $token) = $csrfRegistry->generateTokenAndIdentifier();

        // Create the identifier tag
        $name = $this->prefixFieldName(self::TOKEN_ID_IDENTIFIER);
        $this->registerFieldNameForFormTokenGeneration($name);
        $this->tag->reset();
        $this->tag->setTagName('input');
        $this->tag->addAttributes([
            'type' => 'hidden',
            'name' => $name,
            'value' => $identifier
        ]);
        $out = $this->tag->render();

        // Create the value tag
        $name = $this->prefixFieldName(self::TOKEN_VALUE_IDENTIFIER);
        $this->registerFieldNameForFormTokenGeneration($name);
        $this->tag->reset();
        $this->tag->setTagName('input');
        $this->tag->addAttributes([
            'type' => 'hidden',
            'name' => $name,
            'value' => $token
        ]);
        return $out . $this->tag->render();
    }
}
