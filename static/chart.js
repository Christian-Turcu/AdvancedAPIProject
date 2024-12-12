// Chart color scheme
const chartColors = {
    clean: 'rgba(0, 255, 0, 0.6)',     // Green
    malicious: 'rgba(255, 0, 0, 0.6)',  // Red
    border: '#1a1a2e'
};

// Chart default settings
const chartDefaults = {
    borderWidth: 1,
    fontSize: {
        title: 16,
        normal: 14
    },
    legendPadding: 15
};

// File type categories
const fileCategories = {
    exe: 'Executable',
    dll: 'Dynamic Library',
    doc: 'Document',
    docx: 'Document',
    pdf: 'Document',
    zip: 'Archive',
    rar: 'Archive',
    '7z': 'Archive'
};

// Cleanup old chart if it exists
function cleanupOldChart(canvas) {
    const oldChart = Chart.getChart(canvas);
    if (oldChart) {
        oldChart.destroy();
    }
}

// Main chart initialization function
function initializeChart(canvas, isFolder, data) {
    cleanupOldChart(canvas);
    let ctx = canvas.getContext('2d');
    let chartData;

    if (isFolder) {
        // For folder analysis
        let total = data.total_files || 0;
        if (total === 0) total = 1;

        let cleanPercentage = ((data.clean_files || 0) / total) * 100;
        let maliciousPercentage = ((data.malicious_files || 0) / total) * 100;

        chartData = {
            labels: ['Clean', 'Malicious'],
            datasets: [{
                data: [cleanPercentage, maliciousPercentage],
                backgroundColor: [chartColors.clean, chartColors.malicious],
                borderColor: chartColors.border,
                borderWidth: chartDefaults.borderWidth
            }]
        };
    } else {
        // For single file analysis
        let fileType = canvas.getAttribute('data-file-type');
        let threatLevel = canvas.getAttribute('data-threat-level');
        
        let category = fileCategories[fileType] || 'Unknown';
        let threatColor;
        
        switch(threatLevel) {
            case 'high':
                threatColor = 'rgba(255, 0, 0, 0.6)';
                break;
            case 'medium':
                threatColor = 'rgba(255, 165, 0, 0.6)';
                break;
            case 'low':
                threatColor = 'rgba(255, 255, 0, 0.6)';
                break;
            default:
                threatColor = 'rgba(0, 255, 0, 0.6)';
        }

        chartData = {
            labels: ['Safe (100.0%)', 'Low Risk (0.0%)', 'Medium Risk (0.0%)', 'High Risk (0.0%)'],
            datasets: [{
                data: [100, 0, 0, 0],
                backgroundColor: [
                    'rgba(0, 200, 81, 0.6)',  // Safe - Green
                    'rgba(255, 235, 59, 0.6)', // Low Risk - Yellow
                    'rgba(255, 165, 0, 0.6)',  // Medium Risk - Orange
                    'rgba(255, 68, 68, 0.6)'   // High Risk - Red
                ],
                borderColor: Array(4).fill('rgba(0, 0, 0, 0)'),
                borderWidth: 1
            }]
        };
    }

    new Chart(ctx, {
        type: 'doughnut',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '85%',
            radius: '90%',
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
                }
            },
            elements: {
                arc: {
                    borderWidth: 0,
                    borderRadius: 5
                }
            },
            animation: {
                animateScale: true,
                animateRotate: true,
                duration: 800,
                easing: 'easeOutQuart'
            }
        },
        plugins: [{
            id: 'centerText',
            afterDraw: (chart) => {
                const ctx = chart.ctx;
                const width = chart.width;
                const height = chart.height;
                ctx.restore();
                
                // Calculate the sum of all values
                const data = chart.data.datasets[0].data;
                const total = data.reduce((a, b) => a + b, 0);
                
                // Find the highest value and its index
                const maxValue = Math.max(...data);
                const maxIndex = data.indexOf(maxValue);
                
                // Get the label for the highest value
                const maxLabel = chart.data.labels[maxIndex];
                
                // Text settings
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                
                // Draw percentage
                ctx.font = 'bold 24px Arial';
                ctx.fillStyle = '#00ff00';
                ctx.fillText(maxValue.toFixed(1) + '%', width / 2, height / 2 - 15);
                
                // Draw label
                ctx.font = '16px Arial';
                ctx.fillStyle = '#ffffff';
                ctx.fillText('Safe', width / 2, height / 2 + 15);
                
                ctx.save();
            }
        }]
    });
}

// Try to init the chart - will retry if Chart.js is still loading
let chartInitAttempts = 0;
function tryInitChart() {
    const canvas = document.getElementById('threatChart');
    if (!canvas) return;

    try {
        const isFolder = canvas.hasAttribute('data-folder-stats');
        let data = null;
        
        if (isFolder) {
            const folderStatsStr = canvas.getAttribute('data-folder-stats');
            if (folderStatsStr) {
                data = JSON.parse(folderStatsStr);
            }
        }
        
        initializeChart(canvas, isFolder, data);
    } catch (e) {
        console.error('Error initializing chart:', e);
        if (chartInitAttempts < 5) {
            chartInitAttempts++;
            setTimeout(tryInitChart, 500);
        }
    }
}

document.addEventListener('DOMContentLoaded', tryInitChart);
