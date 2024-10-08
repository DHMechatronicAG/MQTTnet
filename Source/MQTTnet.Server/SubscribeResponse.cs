// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using MQTTnet.Packets;
using MQTTnet.Protocol;

namespace MQTTnet.Server;

public sealed class SubscribeResponse
{
    /// <summary>
    ///     Gets or sets the reason code which is sent to the client.
    ///     The subscription is skipped when the value is not GrantedQoS_.
    ///     MQTTv5 only.
    /// </summary>
    public MqttSubscribeReasonCode ReasonCode { get; set; }

    public string ReasonString { get; set; }

    public List<MqttUserProperty> UserProperties { get; } = new();
}