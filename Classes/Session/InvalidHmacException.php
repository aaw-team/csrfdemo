<?php
declare(strict_types=1);
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

/**
 * InvalidHmacException gets thrown when a HMAC check did not succeed.
 *
 * When catching this exception, be sure to discard all the data with
 * the invalid HMAC!
 */
class InvalidHmacException extends \RuntimeException
{}
