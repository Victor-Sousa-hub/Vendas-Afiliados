anychart.onDocumentReady(function () {
    // Dados do gráfico
     var data = [
        { date: '2024-11-01', open: 20.5, high: 21, low: 20, close: 20.8 },
        { date: '2024-11-02', open: 20.8, high: 21.5, low: 20.3, close: 21.1 },
        { date: '2024-11-03', open: 21.1, high: 22, low: 20.7, close: 21.9 },
        { date: '2024-11-04', open: 21.9, high: 22.5, low: 21.4, close: 22 },
        { date: '2024-11-05', open: 22, high: 22.8, low: 21.9, close: 22.3 },
        { date: '2024-11-06', open: 22.3, high: 23, low: 22, close: 22.8 },
        { date: '2024-11-07', open: 22.8, high: 23.5, low: 22.5, close: 23 },
        { date: '2024-11-08', open: 23, high: 24, low: 22.8, close: 23.8 },
        { date: '2024-11-09', open: 23.8, high: 24.2, low: 23.5, close: 24 },
        { date: '2024-11-10', open: 24, high: 24.5, low: 23.8, close: 24.2 },
        { date: '2024-11-11', open: 24.2, high: 25, low: 24, close: 24.8 },
        { date: '2024-11-12', open: 24.8, high: 25.5, low: 24.5, close: 25 },
        { date: '2024-11-13', open: 25, high: 26, low: 24.8, close: 25.5 },
        { date: '2024-11-14', open: 25.5, high: 26.2, low: 25, close: 25.8 },
        { date: '2024-11-15', open: 25.8, high: 26.5, low: 25.5, close: 26 },
        { date: '2024-11-16', open: 26, high: 27, low: 25.8, close: 26.5 },
        { date: '2024-11-17', open: 26.5, high: 27.5, low: 26, close: 27 },
        { date: '2024-11-18', open: 27, high: 28, low: 26.5, close: 27.5 },
        { date: '2024-11-19', open: 27.5, high: 28.5, low: 27, close: 28 },
        { date: '2024-11-20', open: 28, high: 29, low: 27.5, close: 28.5 },
        { date: '2024-11-21', open: 28.5, high: 29.5, low: 28, close: 29 },
        { date: '2024-11-22', open: 29, high: 30, low: 28.5, close: 29.5 },
        { date: '2024-11-23', open: 29.5, high: 31, low: 29, close: 30 },
        { date: '2024-11-24', open: 30, high: 31.5, low: 29.5, close: 30.5 },
        { date: '2024-11-25', open: 30.5, high: 32, low: 30, close: 31 },
        { date: '2024-11-26', open: 31, high: 32.5, low: 30.5, close: 31.5 },
        { date: '2024-11-27', open: 31.5, high: 33, low: 31, close: 32 },
        { date: '2024-11-28', open: 32, high: 33.5, low: 31.5, close: 32.5 },
        { date: '2024-11-29', open: 32.5, high: 34, low: 32, close: 33 },
        { date: '2024-11-30', open: 33, high: 34.5, low: 32.5, close: 33.5 }
    ];
    // Cria uma tabela de dados
    var dataTable = anychart.data.table('date');
    dataTable.addData(data);

    // Mapeia os dados para candlestick
    var mapping = dataTable.mapAs({
        open: 'open',
        high: 'high',
        low: 'low',
        close: 'close'
    });

    // Cria o gráfico
    var chart = anychart.stock();

    // Adiciona o gráfico de candlestick
    var series = chart.plot(0).candlestick(mapping);
    series.name('Histórico de Preços');

    // Configura as cores das velas
    series.risingFill('#00FF00'); // Verde em alta
    series.risingStroke('#00FF00');
    series.fallingFill('#FF0000'); // Vermelho em baixa
    series.fallingStroke('#FF0000');

    // Configura o título do gráfico
    chart.title('Evolução de Preços - Candlestick');

    // Estiliza o fundo
    chart.background().fill('#151826'); // Fundo do gráfico
    chart.plot(0).background().fill('#151826'); // Fundo da área do gráfico

    // Configura os eixos
    chart.plot(0).xAxis().labels().fontColor('#FFFFFF'); // Rótulos do eixo X em branco
    chart.plot(0).yAxis().labels().fontColor('#FFFFFF'); // Rótulos do eixo Y em branco

    // Configura o contêiner
    chart.container('graficoDesempenho');

    // Renderiza o gráfico
    chart.draw();
});
