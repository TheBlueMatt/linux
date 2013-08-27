/*
 * Shamir's secret sharing public functions
 *
 * Copyright (C) 2013 Matt Corallo <git@bluematt.me>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#ifndef IN_KERNEL
#include <stdint.h>
#else
#include <linux/types.h>
#endif

#define P 256

/**
 * Calculates the Y coordinate that the point with the given X
 * coefficients[0] == secret, the rest are secure random values
 */
uint8_t calculateQ(uint8_t coefficients[], uint8_t shares_required, uint8_t x);

/**
 * Derives the secret given a set of shares_required points (x and q coordinates)
 */
uint8_t calculateSecret(uint8_t x[], uint8_t q[], uint8_t shares_required);
