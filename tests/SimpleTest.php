<?php

class SimpleTest extends phpunit_framework_testcase
{
    /**
     *  @expectedException RuntimeException
     */
    public function testNoCode()
    {
        CSRF::generate();
    }

    public function testValidCode()
    {
        CSRF::setSecret(uniqid(true));
        $code = CSRF::generate();
        $this->assertTrue(CSRF::verify($code));
    }

    public function testInvalidCodeWrongSecret()
    {
        CSRF::setSecret(uniqid(true));
        $code = CSRF::generate();
        CSRF::setSecret(uniqid(true));
        $this->assertFalse(CSRF::verify($code));
    }

    public function testInvalidCodeWrongIP()
    {
        CSRF::setSecret(uniqid(true));
        $_SERVER['REMOTE_ADDR'] = '8.8.8.8';
        $code = CSRF::generate();
        $_SERVER['REMOTE_ADDR'] = '8.8.4.4';
        $this->assertFalse(CSRF::verify($code));
    }
}
