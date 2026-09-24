///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz <rapidrests@gmail.com>
///////////////////////////////////////////////////////////////////////////////
import { BaseStatusRoute, RouteDecorators } from "@rapidrest/service-core";
const { Route } = RouteDecorators;

@Route("/status")
export class StatusRoute extends BaseStatusRoute {}