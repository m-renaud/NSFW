{-# OPTIONS_GHC -F -pgmF htfpp #-}
module Main where

import Test.Framework

import {-@ HTF_TESTS @-} Network.NSFW.Firewall.Rule.Tests

main :: IO ()
main = htfMain htf_importedTests
